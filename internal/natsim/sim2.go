// sim2 simulates the initiator/caller side of eNode's UDP NAT-traversal hole-punch
// (ed2k/nattraversal.go): register, send OP_NAT_SYNC2 to pair with the target hash,
// receive the peer's public endpoint via OP_NAT_SYNC, then punch with PING/PONG. It
// differs from the TCP low-ID callback (OP_CALLBACKREQUEST, server_runtime.go), where
// the firewalled peer dials out over TCP; hole-punching works when both ends are NAT'd.

package natsim

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"enode/ed2k"
)

// Sim2Options configures RunSim2, the initiator/caller NAT-traversal peer. It
// registers, asks the server to pair its hash with the target peer hash
// (OP_NAT_SYNC2), receives the peer endpoint (OP_NAT_SYNC), PINGs it and waits
// for a PONG.
type Sim2Options struct {
	NATAddr      *net.UDPAddr
	Hash         [16]byte
	Peer         [16]byte
	ListenPort   int
	Timeout      time.Duration
	RegisterMode string // "legacy" (OP_NAT_REGISTER) | "ex" (OP_NAT_REGISTER_EX)
	Version      uint8  // client version advertised when RegisterMode == "ex"
	Logger       Logger
}

// Sim2Result reports what RunSim2 observed, for callers and tests.
type Sim2Result struct {
	LocalAddr  *net.UDPAddr
	Registered bool
	Sync       *SyncInfo // set once OP_NAT_SYNC[_EX] arrives; HasVersion => SYNC_EX
	PeerAddr   *net.UDPAddr
	GotPong    bool
}

// RunSim2 drives the full initiator flow and returns once it receives a PONG,
// hits an error, or the context is cancelled.
func RunSim2(ctx context.Context, o Sim2Options) (Sim2Result, error) {
	lg := loggerOrDefault(o.Logger)
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: o.ListenPort})
	if err != nil {
		return Sim2Result{}, fmt.Errorf("listen udp: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	// Closing the conn unblocks the read loop; Wait then joins it so the loop (and
	// its Logger call) cannot outlive RunSim2.
	defer func() {
		cancel()
		conn.Close()
		wg.Wait()
	}()

	local := conn.LocalAddr().(*net.UDPAddr)
	res := Sim2Result{LocalAddr: local}
	lg.Printf("natsim2: local=%s nat=%s hash=%x peer=%x", local.String(), o.NATAddr.String(), o.Hash, o.Peer)

	registerAckCh := make(chan *net.UDPAddr, 1)
	syncCh := make(chan SyncInfo, 1)
	pongCh := make(chan *net.UDPAddr, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		runSim2ReadLoop(conn, lg, registerAckCh, syncCh, pongCh)
	}()

	ex := o.RegisterMode == "ex"
	register := BuildRegisterPacket(o.Hash, ex, o.Version)
	lg.Printf("natsim2: send OP_NAT_REGISTER%s -> %s raw=%s", exSuffix(ex), o.NATAddr.String(), HexDump(register))
	if _, err := conn.WriteToUDP(register, o.NATAddr); err != nil {
		return res, fmt.Errorf("send register: %w", err)
	}

	connAck := RandConnAck()
	sync2 := EncodeNATPacket(ed2k.OpNatSync2, BuildSync2Payload(o.Hash, connAck, o.Peer))
	var natEndpoint *net.UDPAddr
	select {
	case ackEndpoint := <-registerAckCh:
		res.Registered = true
		natEndpoint = ackEndpoint
		if natEndpoint == nil {
			natEndpoint = o.NATAddr
		}
		lg.Printf("natsim2: got OP_NAT_REGISTER ack, sending OP_NAT_SYNC2 to %s", natEndpoint.String())
	case <-time.After(timeout):
		return res, fmt.Errorf("timeout waiting for OP_NAT_REGISTER ack")
	case <-ctx.Done():
		return res, ctx.Err()
	}
	lg.Printf("natsim2: send OP_NAT_SYNC2 -> %s raw=%s", natEndpoint.String(), HexDump(sync2))
	if _, err := conn.WriteToUDP(sync2, natEndpoint); err != nil {
		return res, fmt.Errorf("send sync2: %w", err)
	}

	var peerAddr *net.UDPAddr
	select {
	case info := <-syncCh:
		cp := info
		res.Sync = &cp
		peerAddr = &net.UDPAddr{IP: info.PeerIP, Port: int(info.PeerPort)}
		res.PeerAddr = peerAddr
		lg.Printf("natsim2: NAT sync peer=%s:%d hash=%x connAck=%x", info.PeerIP.String(), info.PeerPort, info.PeerHash, info.ConnAck)
	case <-time.After(timeout):
		return res, fmt.Errorf("timeout waiting for NAT sync")
	case <-ctx.Done():
		return res, ctx.Err()
	}

	if peerAddr == nil || peerAddr.Port == 0 || peerAddr.IP == nil {
		return res, fmt.Errorf("invalid peer from NAT sync")
	}

	if _, err := conn.WriteToUDP([]byte("PING"), peerAddr); err != nil {
		return res, fmt.Errorf("send PING: %w", err)
	}
	lg.Printf("natsim2: sent PING to %s raw=%s", peerAddr.String(), HexDump([]byte("PING")))

	select {
	case addr := <-pongCh:
		res.GotPong = true
		lg.Printf("natsim2: recv PONG from %s", addr.String())
	case <-time.After(timeout):
		return res, fmt.Errorf("timeout waiting for PONG")
	case <-ctx.Done():
		return res, ctx.Err()
	}
	return res, nil
}

func runSim2ReadLoop(conn *net.UDPConn, lg Logger, registerAckCh chan<- *net.UDPAddr, syncCh chan<- SyncInfo, pongCh chan<- *net.UDPAddr) {
	buf := make([]byte, 2048)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		if buf[0] == ed2k.PrNat {
			DispatchNATPacket(
				buf[:n],
				func(endpoint *net.UDPAddr, _ []byte) {
					lg.Printf("natsim2: recv OP_NAT_REGISTER server=%s raw=%s", endpoint.String(), HexDump(buf[:n]))
					select {
					case registerAckCh <- endpoint:
					default:
					}
				},
				func(info SyncInfo, _ []byte) {
					lg.Printf("natsim2: recv OP_NAT_SYNC%s raw=%s", exSuffix(info.HasVersion), HexDump(buf[:n]))
					select {
					case syncCh <- info:
					default:
					}
				},
				func(_ []byte) {
					lg.Printf("natsim2: recv OP_NAT_FAILED raw=%s", HexDump(buf[:n]))
				},
				func(_ []byte) {
					lg.Printf("natsim2: recv OP_NAT_PING raw=%s", HexDump(buf[:n]))
				},
			)
			continue
		}

		if IsPong(buf[:n]) {
			lg.Printf("natsim2: recv PONG from %s raw=%s", remote.String(), HexDump(buf[:n]))
			select {
			case pongCh <- cloneUDPAddr(remote):
			default:
			}
		} else if IsPing(buf[:n]) {
			lg.Printf("natsim2: recv PING from %s raw=%s", remote.String(), HexDump(buf[:n]))
			_ = SendPong(conn, remote)
			lg.Printf("natsim2: sent PONG to %s raw=%s", remote.String(), HexDump([]byte("PONG")))
		} else {
			lg.Printf("natsim2: recv raw len=%d from %s raw=%s", n, remote.String(), HexDump(buf[:n]))
		}
	}
}
