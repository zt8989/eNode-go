package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"

	"enode/internal/natsim"
)

func main() {
	natAddrFlag := flag.String("nat", "127.0.0.1:2004", "NAT server UDP address")
	hashFlag := flag.String("hash", "", "client hash (32 hex chars)")
	peerFlag := flag.String("peer", "", "peer hash (32 hex chars)")
	listenPortFlag := flag.Int("listen", 0, "local UDP port (0 = random)")
	timeoutFlag := flag.Duration("timeout", 30*time.Second, "wait timeout for NAT sync")
	registerModeFlag := flag.String("register-mode", "legacy", "register mode: legacy (OP_NAT_REGISTER) | ex (OP_NAT_REGISTER_EX)")
	versionFlag := flag.Int("version", 0, "client version advertised with -register-mode ex (0-255)")
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
	if *registerModeFlag != "legacy" && *registerModeFlag != "ex" {
		fmt.Fprintf(os.Stderr, "invalid -register-mode: %q (use legacy|ex)\n", *registerModeFlag)
		os.Exit(2)
	}
	if *versionFlag < 0 || *versionFlag > 255 {
		fmt.Fprintf(os.Stderr, "invalid -version: %d (use 0-255)\n", *versionFlag)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	res, err := natsim.RunSim2(ctx, natsim.Sim2Options{
		NATAddr:      natAddr,
		Hash:         hash,
		Peer:         peerHash,
		ListenPort:   *listenPortFlag,
		Timeout:      *timeoutFlag,
		RegisterMode: *registerModeFlag,
		Version:      uint8(*versionFlag),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "natsim2: %v\n", err)
		os.Exit(1)
	}
	if !res.GotPong {
		fmt.Fprintln(os.Stderr, "natsim2: finished without a PONG")
		os.Exit(1)
	}
}
