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
	listenPortFlag := flag.Int("listen", 0, "local UDP port (0 = random)")
	timeoutFlag := flag.Duration("timeout", 30*time.Second, "wait timeout for NAT sync")
	registerIntervalFlag := flag.Duration("register-interval", 90*time.Second, "OP_NAT_REGISTER resend interval (0 to disable)")
	keepaliveIntervalFlag := flag.Duration("keepalive-interval", 20*time.Second, "UDP keepalive interval to NAT server (0 to disable)")
	keepaliveModeFlag := flag.String("keepalive-mode", "legacy", "keepalive mode: legacy|nat")
	registerModeFlag := flag.String("register-mode", "legacy", "register mode: legacy (OP_NAT_REGISTER) | ex (OP_NAT_REGISTER_EX)")
	versionFlag := flag.Int("version", 0, "client version advertised with -register-mode ex (0-255)")
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

	_, err = natsim.RunSim1(ctx, natsim.Sim1Options{
		NATAddr:           natAddr,
		Hash:              hash,
		ListenPort:        *listenPortFlag,
		Timeout:           *timeoutFlag,
		RegisterInterval:  *registerIntervalFlag,
		KeepaliveInterval: *keepaliveIntervalFlag,
		KeepaliveMode:     *keepaliveModeFlag,
		RegisterMode:      *registerModeFlag,
		Version:           uint8(*versionFlag),
		PingAfterSync:     *pingAfterSyncFlag,
		ExitAfterPong:     *exitAfterPongFlag,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "natsim1: %v\n", err)
		os.Exit(1)
	}
}
