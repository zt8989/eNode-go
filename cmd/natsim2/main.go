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
	peerFlag := flag.String("peer", "", "peer hash (32 hex chars)")
	listenPortFlag := flag.Int("listen", 0, "local UDP port (0 = random)")
	timeoutFlag := flag.Duration("timeout", 30*time.Second, "wait timeout for NAT sync")
	flag.Parse()

	if *hashFlag == "" || *peerFlag == "" {
		fmt.Fprintln(os.Stderr, "missing -hash or -peer")
		os.Exit(2)
	}
	hash, err := natsim.ParseHashHex(*hashFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -hash: %v\n", err)
		os.Exit(2)
	}
	peerHash, err := natsim.ParseHashHex(*peerFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -peer: %v\n", err)
		os.Exit(2)
	}

	natAddr, err := net.ResolveUDPAddr("udp", *natAddrFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -nat: %v\n", err)
		os.Exit(2)
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: *listenPortFlag})
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen udp: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	log.Printf("natsim2: local=%s nat=%s hash=%x peer=%x", conn.LocalAddr().String(), natAddr.String(), hash, peerHash)

	register := natsim.EncodeNATPacket(ed2k.OpNatRegister, hash[:])
	log.Printf("natsim2: send OP_NAT_REGISTER -> %s raw=%s", natAddr.String(), natsim.HexDump(register))
	if _, err := conn.WriteToUDP(register, natAddr); err != nil {
		fmt.Fprintf(os.Stderr, "send register: %v\n", err)
		os.Exit(1)
	}

	registerAckCh := make(chan *net.UDPAddr, 1)
	syncCh := make(chan natsim.SyncInfo, 1)
	pongCh := make(chan *net.UDPAddr, 1)
	go readLoop(conn, registerAckCh, syncCh, pongCh)

	connAck := natsim.RandConnAck()
	sync2Payload := natsim.BuildSync2Payload(hash, connAck, peerHash)
	sync2 := natsim.EncodeNATPacket(ed2k.OpNatSync2, sync2Payload)
	var natEndpoint *net.UDPAddr
	select {
	case ackEndpoint := <-registerAckCh:
		natEndpoint = ackEndpoint
		if natEndpoint == nil {
			natEndpoint = natAddr
		}
		log.Printf("natsim2: got OP_NAT_REGISTER ack, sending OP_NAT_SYNC2 to %s", natEndpoint.String())
	case <-time.After(*timeoutFlag):
		log.Printf("natsim2: timeout waiting for OP_NAT_REGISTER ack")
		os.Exit(1)
	}
	log.Printf("natsim2: send OP_NAT_SYNC2 -> %s raw=%s", natEndpoint.String(), natsim.HexDump(sync2))
	if _, err := conn.WriteToUDP(sync2, natEndpoint); err != nil {
		fmt.Fprintf(os.Stderr, "send sync2: %v\n", err)
		os.Exit(1)
	}

	var peerAddr *net.UDPAddr
	select {
	case info := <-syncCh:
		peerAddr = &net.UDPAddr{IP: info.PeerIP, Port: int(info.PeerPort)}
		log.Printf("natsim2: NAT sync peer=%s:%d hash=%x connAck=%x", info.PeerIP.String(), info.PeerPort, info.PeerHash, info.ConnAck)
	case <-time.After(*timeoutFlag):
		log.Printf("natsim2: timeout waiting for NAT sync")
		os.Exit(1)
	}

	if peerAddr == nil || peerAddr.Port == 0 || peerAddr.IP == nil {
		log.Printf("natsim2: invalid peer from NAT sync")
		os.Exit(1)
	}

	if _, err := conn.WriteToUDP([]byte("PING"), peerAddr); err != nil {
		fmt.Fprintf(os.Stderr, "send PING: %v\n", err)
		os.Exit(1)
	}
	log.Printf("natsim2: sent PING to %s raw=%s", peerAddr.String(), natsim.HexDump([]byte("PING")))

	select {
	case addr := <-pongCh:
		log.Printf("natsim2: recv PONG from %s", addr.String())
	case <-time.After(*timeoutFlag):
		log.Printf("natsim2: timeout waiting for PONG")
		os.Exit(1)
	}
}

func readLoop(conn *net.UDPConn, registerAckCh chan<- *net.UDPAddr, syncCh chan<- natsim.SyncInfo, pongCh chan<- *net.UDPAddr) {
	buf := make([]byte, 2048)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("natsim2: read error: %v", err)
			return
		}
		if n == 0 {
			continue
		}
		if buf[0] == ed2k.PrNat {
			opcode, payload, ok := natsim.DecodeNATPacket(buf[:n])
			if !ok {
				continue
			}
			switch opcode {
			case ed2k.OpNatRegister:
				if len(payload) >= 6 {
					port := int(payload[0])<<8 | int(payload[1])
					ip := net.IPv4(payload[2], payload[3], payload[4], payload[5])
					log.Printf("natsim2: recv OP_NAT_REGISTER server=%s:%d raw=%s", ip.String(), port, natsim.HexDump(buf[:n]))
					endpoint := &net.UDPAddr{IP: append(net.IP(nil), ip...), Port: port}
					select {
					case registerAckCh <- endpoint:
					default:
					}
				}
			case ed2k.OpNatSync:
				if info, ok := natsim.DecodeSyncPayload(payload); ok {
					log.Printf("natsim2: recv OP_NAT_SYNC raw=%s", natsim.HexDump(buf[:n]))
					select {
					case syncCh <- info:
					default:
					}
				}
			case ed2k.OpNatFailed:
				log.Printf("natsim2: recv OP_NAT_FAILED raw=%s", natsim.HexDump(buf[:n]))
			}
			continue
		}

		if n == 4 && string(buf[:n]) == "PONG" {
			log.Printf("natsim2: recv PONG from %s raw=%s", remote.String(), natsim.HexDump(buf[:n]))
			select {
			case pongCh <- remote:
			default:
			}
		} else if n == 4 && string(buf[:n]) == "PING" {
			log.Printf("natsim2: recv PING from %s raw=%s", remote.String(), natsim.HexDump(buf[:n]))
			out := []byte("PONG")
			_, _ = conn.WriteToUDP(out, remote)
			log.Printf("natsim2: sent PONG to %s raw=%s", remote.String(), natsim.HexDump(out))
		} else {
			log.Printf("natsim2: recv raw len=%d from %s raw=%s", n, remote.String(), natsim.HexDump(buf[:n]))
		}
	}
}
