package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"enode/ed2k"
	"enode/internal/natsim"
)

func main() {
	natAddrFlag := flag.String("nat", "127.0.0.1:2004", "NAT server UDP address")
	hashFlag := flag.String("hash", "", "client hash (32 hex chars)")
	listenPortFlag := flag.Int("listen", 0, "local UDP port (0 = random)")
	timeoutFlag := flag.Duration("timeout", 30*time.Second, "wait timeout for NAT sync")
	registerIntervalFlag := flag.Duration("register-interval", 90*time.Second, "OP_NAT_REGISTER resend interval (0 to disable)")
	keepaliveIntervalFlag := flag.Duration("keepalive-interval", 20*time.Second, "UDP keepalive interval to NAT server (0 to disable)")
	keepaliveModeFlag := flag.String("keepalive-mode", "legacy", "keepalive mode: legacy|nat")
	pingAfterSyncFlag := flag.Bool("ping-after-sync", true, "send UDP PING to peer after OP_NAT_SYNC")
	exitAfterPongFlag := flag.Bool("exit-after-pong", false, "exit after responding to a single PING")
	flag.Parse()

	if *hashFlag == "" {
		fmt.Fprintln(os.Stderr, "missing -hash")
		os.Exit(2)
	}
	hash, err := natsim.ParseHashHex(*hashFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -hash: %v\n", err)
		os.Exit(2)
	}

	natAddr, err := net.ResolveUDPAddr("udp", *natAddrFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -nat: %v\n", err)
		os.Exit(2)
	}
	if *keepaliveModeFlag != "legacy" && *keepaliveModeFlag != "nat" {
		fmt.Fprintf(os.Stderr, "invalid -keepalive-mode: %q (use legacy|nat)\n", *keepaliveModeFlag)
		os.Exit(2)
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: *listenPortFlag})
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen udp: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	log.Printf("natsim1: local=%s nat=%s hash=%x", conn.LocalAddr().String(), natAddr.String(), hash)
	endpointStore := natsim.NewEndpointStore(natAddr)

	register := natsim.EncodeNATPacket(ed2k.OpNatRegister, hash[:])
	log.Printf("natsim1: send OP_NAT_REGISTER -> %s raw=%s", natAddr.String(), natsim.HexDump(register))
	if _, err := conn.WriteToUDP(register, natAddr); err != nil {
		fmt.Fprintf(os.Stderr, "send register: %v\n", err)
		os.Exit(1)
	}

	registerAckCh := make(chan struct{}, 1)
	syncCh := make(chan natsim.SyncInfo, 1)
	pongDone := make(chan struct{}, 1)
	go readLoop(conn, endpointStore, registerAckCh, syncCh, pongDone, *exitAfterPongFlag)

	select {
	case <-registerAckCh:
		log.Printf("natsim1: got OP_NAT_REGISTER ack, ready for NAT sync and PING")
		if *registerIntervalFlag > 0 {
			go registerLoop(conn, endpointStore, natAddr, hash, *registerIntervalFlag)
		}
		if *keepaliveIntervalFlag > 0 {
			go keepaliveLoop(conn, endpointStore, natAddr, *keepaliveIntervalFlag, *keepaliveModeFlag)
		}
	case <-time.After(*timeoutFlag):
		log.Printf("natsim1: timeout waiting for OP_NAT_REGISTER ack")
		return
	}

	select {
	case info := <-syncCh:
		log.Printf("natsim1: NAT sync peer=%s:%d hash=%x connAck=%x", info.PeerIP.String(), info.PeerPort, info.PeerHash, info.ConnAck)
		if *pingAfterSyncFlag {
			peerAddr := &net.UDPAddr{IP: info.PeerIP, Port: int(info.PeerPort)}
			if _, err := conn.WriteToUDP([]byte("PING"), peerAddr); err != nil {
				log.Printf("natsim1: send PING error: %v", err)
			} else {
				log.Printf("natsim1: sent PING to %s raw=%s", peerAddr.String(), natsim.HexDump([]byte("PING")))
			}
		}
	case <-time.After(*timeoutFlag):
		log.Printf("natsim1: timeout waiting for NAT sync")
	}

	if *exitAfterPongFlag {
		select {
		case <-pongDone:
		case <-time.After(*timeoutFlag):
			log.Printf("natsim1: timeout waiting for PING/PONG")
		}
		return
	}

	select {}
}

func readLoop(conn *net.UDPConn, endpointStore *natsim.EndpointStore, registerAckCh chan<- struct{}, syncCh chan<- natsim.SyncInfo, pongDone chan<- struct{}, exitAfterPong bool) {
	buf := make([]byte, 2048)
	registered := false
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("natsim1: read error: %v", err)
			return
		}
		if n == 0 {
			continue
		}
		if n > 0 && buf[0] == ed2k.PrNat {
			natsim.DispatchNATPacket(
				buf[:n],
				func(endpoint *net.UDPAddr, _ []byte) {
					log.Printf("natsim1: recv OP_NAT_REGISTER server=%s raw=%s", endpoint.String(), natsim.HexDump(buf[:n]))
					endpointStore.Set(endpoint)
					if !registered {
						registered = true
						select {
						case registerAckCh <- struct{}{}:
						default:
						}
					}
				},
				func(info natsim.SyncInfo, _ []byte) {
					if !registered {
						log.Printf("natsim1: ignore OP_NAT_SYNC before register ack")
						return
					}
					log.Printf("natsim1: recv OP_NAT_SYNC raw=%s", natsim.HexDump(buf[:n]))
					select {
					case syncCh <- info:
					default:
					}
				},
				nil,
			)
			continue
		}

		if !registered {
			log.Printf("natsim1: ignore non-NAT before register ack len=%d from %s", n, remote.String())
			continue
		}
		if natsim.IsPing(buf[:n]) {
			log.Printf("natsim1: recv PING from %s raw=%s", remote.String(), natsim.HexDump(buf[:n]))
			_ = natsim.SendPong(conn, remote)
			log.Printf("natsim1: sent PONG to %s raw=%s", remote.String(), natsim.HexDump([]byte("PONG")))
			if exitAfterPong {
				select {
				case pongDone <- struct{}{}:
				default:
				}
				return
			}
		} else if natsim.IsPong(buf[:n]) {
			log.Printf("natsim1: recv PONG from %s raw=%s", remote.String(), natsim.HexDump(buf[:n]))
		} else {
			log.Printf("natsim1: recv raw len=%d from %s raw=%s", n, remote.String(), natsim.HexDump(buf[:n]))
		}
	}
}

func registerLoop(conn *net.UDPConn, endpointStore *natsim.EndpointStore, natAddr *net.UDPAddr, hash [16]byte, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		<-ticker.C
		target := endpointStore.GetOr(natAddr)
		packet := natsim.EncodeNATPacket(ed2k.OpNatRegister, hash[:])
		_, err := conn.WriteToUDP(packet, target)
		if err != nil {
			log.Printf("natsim1: register resend error: %v", err)
			continue
		}
		log.Printf("natsim1: resend OP_NAT_REGISTER -> %s raw=%s", target.String(), natsim.HexDump(packet))
	}
}

func keepaliveLoop(conn *net.UDPConn, endpointStore *natsim.EndpointStore, natAddr *net.UDPAddr, interval time.Duration, mode string) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	payload := []byte{0x00}
	if mode == "nat" {
		payload = natsim.EncodeNATPacket(ed2k.OpNatKeepAlive, nil)
	}
	for {
		<-ticker.C
		target := endpointStore.GetOr(natAddr)
		_, err := conn.WriteToUDP(payload, target)
		if err != nil {
			log.Printf("natsim1: keepalive error: %v", err)
			continue
		}
		log.Printf("natsim1: send keepalive mode=%s -> %s raw=%s", mode, target.String(), natsim.HexDump(payload))
	}
}
