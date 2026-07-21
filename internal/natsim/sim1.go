// sim1 simulates the target/callee side of eNode's UDP NAT-traversal hole-punch
// (ed2k/nattraversal.go): register + keepalive to hold a NAT mapping, wait for the
// server-relayed OP_NAT_SYNC peer endpoint, then punch with PING/PONG. This differs
// from the TCP low-ID callback (OP_CALLBACKREQUEST, server_runtime.go), which reaches
// one firewalled peer over TCP; UDP hole-punching is for when both ends are NAT'd.

package natsim

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"enode/ed2k"
)

// Sim1Options configures RunSim1, the target/callee NAT-traversal peer. It
// registers with the NAT server, keeps itself alive, waits for the server to
// push an OP_NAT_SYNC, then hole-punches the peer with a PING and answers
// incoming PINGs with PONG.
type Sim1Options struct {
	NATAddr           *net.UDPAddr
	Hash              [16]byte
	ListenPort        int
	Timeout           time.Duration
	RegisterInterval  time.Duration
	KeepaliveInterval time.Duration
	KeepaliveMode     string // "legacy" (raw 1-byte) | "nat" (OP_NAT_KEEPALIVE)
	RegisterMode      string // "legacy" (OP_NAT_REGISTER) | "ex" (OP_NAT_REGISTER_EX)
	Version           uint8  // client version advertised when RegisterMode == "ex"
	PingAfterSync     bool
	ExitAfterPong     bool
	Logger            Logger
	// Ready, when non-nil, receives a single value once this peer is registered
	// with the NAT server. Callers that must sequence an initiator after this
	// target is up (tests, scripts) wait on it before triggering the pairing. The
	// send is non-blocking, so it never stalls RunSim1.
	Ready chan<- struct{}
}

// Sim1Result reports what RunSim1 observed, for callers and tests.
type Sim1Result struct {
	LocalAddr     *net.UDPAddr
	Registered    bool
	Sync          *SyncInfo // set once OP_NAT_SYNC[_EX] arrives; HasVersion => SYNC_EX
	PingsAnswered int       // peer PINGs answered with PONG
	NatPings      int       // OP_NAT_PING keepalive ACKs received from the server
}

// RunSim1 runs the target peer until it exits after a PONG (ExitAfterPong) or
// the context is cancelled. It returns a snapshot of what it observed.
func RunSim1(ctx context.Context, o Sim1Options) (Sim1Result, error) {
	lg := loggerOrDefault(o.Logger)
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: o.ListenPort})
	if err != nil {
		return Sim1Result{}, fmt.Errorf("listen udp: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	// Cleanup ordering matters: cancel stops the resend/keepalive loops, closing
	// the conn unblocks the read loop's ReadFromUDP, then Wait joins them so no
	// goroutine (or its Logger call) outlives RunSim1.
	defer func() {
		cancel()
		conn.Close()
		wg.Wait()
	}()

	local := conn.LocalAddr().(*net.UDPAddr)
	st := &sim1State{local: local}
	lg.Printf("natsim1: local=%s nat=%s hash=%x", local.String(), o.NATAddr.String(), o.Hash)
	store := NewEndpointStore(o.NATAddr)

	registerAckCh := make(chan struct{}, 1)
	syncCh := make(chan SyncInfo, 1)
	pongDone := make(chan struct{}, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		runSim1ReadLoop(conn, lg, store, st, o.ExitAfterPong, registerAckCh, syncCh, pongDone)
	}()

	ex := o.RegisterMode == "ex"
	register := BuildRegisterPacket(o.Hash, ex, o.Version)
	lg.Printf("natsim1: send OP_NAT_REGISTER%s -> %s raw=%s", exSuffix(ex), o.NATAddr.String(), HexDump(register))
	if _, err := conn.WriteToUDP(register, o.NATAddr); err != nil {
		return st.snapshot(), fmt.Errorf("send register: %w", err)
	}

	select {
	case <-registerAckCh:
		lg.Printf("natsim1: got OP_NAT_REGISTER ack, ready for NAT sync and PING")
		if o.Ready != nil {
			select {
			case o.Ready <- struct{}{}:
			default:
			}
		}
		if o.RegisterInterval > 0 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				registerLoop1(ctx, conn, lg, store, o)
			}()
		}
		if o.KeepaliveInterval > 0 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				keepaliveLoop1(ctx, conn, lg, store, o)
			}()
		}
	case <-time.After(timeout):
		lg.Printf("natsim1: timeout waiting for OP_NAT_REGISTER ack")
		return st.snapshot(), nil
	case <-ctx.Done():
		return st.snapshot(), ctx.Err()
	}

	select {
	case info := <-syncCh:
		lg.Printf("natsim1: NAT sync peer=%s:%d hash=%x connAck=%x", info.PeerIP.String(), info.PeerPort, info.PeerHash, info.ConnAck)
		if o.PingAfterSync {
			peerAddr := &net.UDPAddr{IP: info.PeerIP, Port: int(info.PeerPort)}
			if _, err := conn.WriteToUDP([]byte("PING"), peerAddr); err != nil {
				lg.Printf("natsim1: send PING error: %v", err)
			} else {
				lg.Printf("natsim1: sent PING to %s raw=%s", peerAddr.String(), HexDump([]byte("PING")))
			}
		}
	case <-time.After(timeout):
		lg.Printf("natsim1: timeout waiting for NAT sync")
	case <-ctx.Done():
		return st.snapshot(), ctx.Err()
	}

	if o.ExitAfterPong {
		select {
		case <-pongDone:
		case <-time.After(timeout):
			lg.Printf("natsim1: timeout waiting for PING/PONG")
		case <-ctx.Done():
		}
		return st.snapshot(), nil
	}

	// Otherwise keep serving PINGs/keepalives until the context is cancelled.
	<-ctx.Done()
	return st.snapshot(), nil
}

// exSuffix renders the "_EX" opcode-name suffix for register-mode logging.
func exSuffix(ex bool) string {
	if ex {
		return "_EX"
	}
	return ""
}

// sim1State is the read loop's shared, mutable view; the read loop writes it and
// RunSim1 snapshots it (possibly while the loop is still running under
// ExitAfterPong==false), so every field is mutex-guarded.
type sim1State struct {
	mu            sync.Mutex
	local         *net.UDPAddr
	registered    bool
	sync          *SyncInfo
	pingsAnswered int
	natPings      int
}

func (s *sim1State) markRegistered() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registered {
		return false
	}
	s.registered = true
	return true
}

func (s *sim1State) isRegistered() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.registered
}

func (s *sim1State) setSync(info SyncInfo) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sync != nil {
		return false
	}
	cp := info
	s.sync = &cp
	return true
}

func (s *sim1State) incPingAnswered() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pingsAnswered++
	return s.pingsAnswered
}

func (s *sim1State) incNatPing() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.natPings++
	return s.natPings
}

func (s *sim1State) snapshot() Sim1Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Sim1Result{
		LocalAddr:     s.local,
		Registered:    s.registered,
		Sync:          s.sync,
		PingsAnswered: s.pingsAnswered,
		NatPings:      s.natPings,
	}
}

func runSim1ReadLoop(conn *net.UDPConn, lg Logger, store *EndpointStore, st *sim1State, exitAfterPong bool, registerAckCh chan<- struct{}, syncCh chan<- SyncInfo, pongDone chan<- struct{}) {
	buf := make([]byte, 2048)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			return // conn closed on shutdown; not a reportable error
		}
		if n == 0 {
			continue
		}
		if buf[0] == ed2k.PrNat {
			DispatchNATPacket(
				buf[:n],
				func(endpoint *net.UDPAddr, _ []byte) {
					lg.Printf("natsim1: recv OP_NAT_REGISTER server=%s raw=%s", endpoint.String(), HexDump(buf[:n]))
					store.Set(endpoint)
					if st.markRegistered() {
						select {
						case registerAckCh <- struct{}{}:
						default:
						}
					}
				},
				func(info SyncInfo, _ []byte) {
					if !st.isRegistered() {
						lg.Printf("natsim1: ignore OP_NAT_SYNC before register ack")
						return
					}
					lg.Printf("natsim1: recv OP_NAT_SYNC%s raw=%s", exSuffix(info.HasVersion), HexDump(buf[:n]))
					if st.setSync(info) {
						select {
						case syncCh <- info:
						default:
						}
					}
				},
				nil,
				func(_ []byte) {
					count := st.incNatPing()
					lg.Printf("natsim1: recv OP_NAT_PING (keepalive ack) count=%d raw=%s", count, HexDump(buf[:n]))
				},
			)
			continue
		}

		if !st.isRegistered() {
			lg.Printf("natsim1: ignore non-NAT before register ack len=%d from %s", n, remote.String())
			continue
		}
		if IsPing(buf[:n]) {
			lg.Printf("natsim1: recv PING from %s raw=%s", remote.String(), HexDump(buf[:n]))
			_ = SendPong(conn, remote)
			count := st.incPingAnswered()
			lg.Printf("natsim1: sent PONG to %s raw=%s (answered=%d)", remote.String(), HexDump([]byte("PONG")), count)
			if exitAfterPong {
				select {
				case pongDone <- struct{}{}:
				default:
				}
				return
			}
		} else if IsPong(buf[:n]) {
			lg.Printf("natsim1: recv PONG from %s raw=%s", remote.String(), HexDump(buf[:n]))
		} else {
			lg.Printf("natsim1: recv raw len=%d from %s raw=%s", n, remote.String(), HexDump(buf[:n]))
		}
	}
}

func registerLoop1(ctx context.Context, conn *net.UDPConn, lg Logger, store *EndpointStore, o Sim1Options) {
	ticker := time.NewTicker(o.RegisterInterval)
	defer ticker.Stop()
	ex := o.RegisterMode == "ex"
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			target := store.GetOr(o.NATAddr)
			packet := BuildRegisterPacket(o.Hash, ex, o.Version)
			if _, err := conn.WriteToUDP(packet, target); err != nil {
				lg.Printf("natsim1: register resend error: %v", err)
				continue
			}
			lg.Printf("natsim1: resend OP_NAT_REGISTER%s -> %s raw=%s", exSuffix(ex), target.String(), HexDump(packet))
		}
	}
}

func keepaliveLoop1(ctx context.Context, conn *net.UDPConn, lg Logger, store *EndpointStore, o Sim1Options) {
	ticker := time.NewTicker(o.KeepaliveInterval)
	defer ticker.Stop()
	payload := []byte{0x00}
	if o.KeepaliveMode == "nat" {
		payload = EncodeNATPacket(ed2k.OpNatKeepAlive, nil)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			target := store.GetOr(o.NATAddr)
			if _, err := conn.WriteToUDP(payload, target); err != nil {
				lg.Printf("natsim1: keepalive error: %v", err)
				continue
			}
			lg.Printf("natsim1: send keepalive mode=%s -> %s raw=%s", o.KeepaliveMode, target.String(), HexDump(payload))
		}
	}
}
