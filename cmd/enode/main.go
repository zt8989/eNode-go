package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"enode/config"
	"enode/ed2k"
	"enode/logging"
	"enode/storage"
)

const backgroundEnvKey = "ENODE_BACKGROUND"

func main() {
	configPath := flag.String("config", "enode.config.yaml", "path to YAML config")
	daemon := flag.Bool("daemon", false, "run in background")
	flag.Parse()

	if *daemon && os.Getenv(backgroundEnvKey) != "1" {
		pid, err := startBackgroundProcess(filterDaemonArgs(os.Args[1:]))
		if err != nil {
			log.Fatalf("start background process failed: %v", err)
		}
		log.Printf("enode started in background, pid=%d", pid)
		return
	}

	// SIGINT/SIGTERM cancel the context, which returns run() and lets its defers
	// execute. Previously main ended in `select {}`, so every defer below —
	// engine.Close(), the listener closes, the cleanup stoppers — was unreachable
	// and only gave the appearance of a graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, *configPath); err != nil {
		logging.Errorf("enode exiting: %v", err)
		os.Exit(1)
	}
	logging.Infof("enode stopped cleanly")
}

// run holds the whole server lifetime. It returns when ctx is cancelled, so the
// defers registered inside it actually run.
//
// Errors after this point are returned rather than passed to logging.Fatalf:
// that is zap's Fatalf, which calls os.Exit(1) and therefore skips every defer
// already registered — including engine.Close(). A signal handler alone would
// not have fixed those paths.
func run(ctx context.Context, configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("config load failed: %w", err)
	}
	// Logging is configured before the dynIp probe so its warnings survive. The
	// probe used to run first and exit via the stdlib logger on failure, and
	// -daemon wires stderr to /dev/null — so a daemonized server that could not
	// reach the internet died with no diagnostic anywhere.
	if err := logging.SetOutputFile(cfg.LogFile); err != nil {
		return fmt.Errorf("config logFile invalid: %w", err)
	}
	if err := logging.SetLevelFromString(cfg.LogLevel); err != nil {
		return fmt.Errorf("config logLevel invalid: %w", err)
	}
	logging.Infof("welcome: enode starting (config=%s)", configPath)

	resolvedDynIP, resolvedByURL, err := resolveDynIPValue(cfg.DynIP, cfg.TestURLs, 0)
	if err != nil {
		// Not fatal. Every consumer of DynIP already degrades: firstRoutableIP
		// prefers cfg.Address, serverIdentitySeed falls back to the hostname, and
		// the NAT endpoint has its own fallback. Refusing to boot because a
		// third-party echo service is unreachable is far harsher than warranted.
		logging.Warnf("dynIp auto resolve failed, continuing without it: %v", err)
		resolvedDynIP = ""
	}
	if resolvedByURL != "" {
		logging.Infof("dynIp auto resolved: %s (url=%s)", resolvedDynIP, resolvedByURL)
	}
	cfg.DynIP = resolvedDynIP

	engine, err := storage.NewEngine(cfg.StorageEngineConfig())
	if err != nil {
		return fmt.Errorf("storage engine create failed: %w", err)
	}
	if err := engine.Init(); err != nil {
		return fmt.Errorf("storage init failed: %w", err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			logging.Warnf("storage close error: %v", err)
		}
	}()

	seedServers(engine, cfg.Servers)

	if cfg.Storage.Cleanup.Enabled {
		keepZeroSourceFiles := cfg.Storage.Cleanup.KeepZeroSourceFilesOrDefault()
		stopStorageCleanup := storage.StartCleanup(
			engine,
			time.Duration(cfg.Storage.Cleanup.IntervalMinutes)*time.Minute,
			time.Duration(cfg.Storage.Cleanup.StaleAfterHours)*time.Hour,
			storage.CleanupOptions{
				KeepZeroSourceFiles: keepZeroSourceFiles,
				BatchSize:           cfg.Storage.Cleanup.BatchSize,
			},
		)
		defer stopStorageCleanup()
		logging.Infof("storage cleanup enabled: every %dm, stale after %dh, keepZeroSourceFiles=%t",
			cfg.Storage.Cleanup.IntervalMinutes, cfg.Storage.Cleanup.StaleAfterHours, keepZeroSourceFiles)
	}

	tcpCfg := ed2k.TCPServerConfig{
		Address:        cfg.Address,
		Port:           cfg.TCP.Port,
		MaxConnections: cfg.TCP.MaxConnections,
		AuxiliarPort:   cfg.AuxiliarPort,
		RequireCrypt:   cfg.RequireCrypt,
		RequestCrypt:   cfg.RequestCrypt,
		SupportCrypt:   cfg.SupportCrypt,
		IPInLogin:      cfg.IPInLogin,
	}
	udpCfg := ed2k.UDPServerConfig{
		Address:      cfg.Address,
		Port:         cfg.UDP.Port,
		GetSources:   cfg.UDP.GetSources,
		GetFiles:     cfg.UDP.GetFiles,
		SupportCrypt: cfg.SupportCrypt,
	}
	tcpFlags := ed2k.BuildTCPFlags(tcpCfg)
	udpFlags := ed2k.BuildUDPFlags(udpCfg)

	// The address clients are told to reach us on. cfg.Address is the *bind*
	// address and defaults to 0.0.0.0, which IPv4ToInt32LE encodes as 0 — so
	// OP_SERVERIDENT advertised server IP 0.0.0.0 to everyone. The UDP path
	// already falls back to DynIP; this gives the TCP ident path the same.
	advertisedIP := firstRoutableIP(cfg.Address, cfg.DynIP)
	if advertisedIP == "" {
		logging.Warnf("advertised server IP unresolved: address=%q dynIp=%q, clients will receive serverIP=0.0.0.0",
			cfg.Address, cfg.DynIP)
	} else if advertisedIP != cfg.Address {
		logging.Infof("advertising server IP %s (address=%q is not routable)", advertisedIP, cfg.Address)
	}

	serverHash := ed2k.MD5([]byte(fmt.Sprintf("%s%d", serverIdentitySeed(advertisedIP, cfg.Address), cfg.TCP.Port)))

	runtime := ed2k.NewServerRuntime(
		ed2k.TCPRuntimeConfig{
			Name:        cfg.Name,
			Description: cfg.Description,
			// Address stays the bind address: probeClient uses it as its
			// LocalAddr and special-cases the wildcard. AdvertisedIP is what goes
			// out in OP_SERVERIDENT.
			Address:           cfg.Address,
			AdvertisedIP:      advertisedIP,
			Port:              cfg.TCP.Port,
			Flags:             tcpFlags,
			Hash:              serverHash,
			MessageLogin:      cfg.MessageLogin,
			MessageLowID:      cfg.MessageLowID,
			ConnectionTimeout: time.Duration(cfg.TCP.ConnectionTimeout) * time.Millisecond,
			DisconnectTimeout: time.Duration(cfg.TCP.DisconnectTimeout) * time.Second,
			AllowLowIDs:       cfg.TCP.AllowLowIDs,
			SupportCrypt:      cfg.SupportCrypt,
			MinLowID:          cfg.TCP.MinLowID,
			MaxLowID:          cfg.TCP.MaxLowID,
		},
		ed2k.UDPRuntimeConfig{
			Name:        cfg.Name,
			Description: cfg.Description,
			DynIP:       cfg.DynIP,
			UDPFlags:    udpFlags,
			// The same two options BuildUDPFlags advertises. They must reach the
			// dispatcher too, or the server clears the flag and keeps answering.
			GetSources:     cfg.UDP.GetSources,
			GetFiles:       cfg.UDP.GetFiles,
			UDPPortObf:     cfg.UDP.PortObfuscated,
			TCPPortObf:     cfg.TCP.PortObfuscated,
			UDPServerKey:   cfg.UDP.ServerKey,
			MaxConnections: uint32(cfg.TCP.MaxConnections),
		},
		engine,
	)

	ln, err := ed2k.RunTCPServer(tcpCfg, runtime.TCPHandler(false))
	if err != nil {
		return fmt.Errorf("tcp server failed: %w", err)
	}
	defer ln.Close()
	logging.Infof("listening: tcp %s:%d", tcpCfg.Address, tcpCfg.Port)

	udpMainHandler := runtime.UDPHandler(false)
	if cfg.NAT.Enabled {
		natTTL := time.Duration(cfg.NAT.RegistrationTTLSeconds) * time.Second
		natHandler := ed2k.NewNATTraversalHandler(natTTL)
		natHandler.ConfigureRegisterEndpointFromConfig(cfg.DynIP, cfg.Address, cfg.UDP.Port)
		natHandler.SetRegisterEndpointForLocalPort(cfg.NAT.Port, cfg.UDP.Port)
		if cfg.SupportCrypt && cfg.UDP.PortObfuscated != 0 {
			natHandler.SetRegisterEndpointForLocalPort(cfg.UDP.PortObfuscated, cfg.UDP.PortObfuscated)
		}
		runtime.SetNATHandler(natHandler)
		effectiveIP := cfg.DynIP
		if effectiveIP == "" {
			effectiveIP = cfg.Address
		}
		if effectiveIP == "" || effectiveIP == "0.0.0.0" {
			logging.Warnf("nat register endpoint unresolved: dynIp=%q address=%q, clients may receive serverIP=0.0.0.0", cfg.DynIP, cfg.Address)
		}
		cleanupInterval := natTTL / 2
		if cleanupInterval < 5*time.Second {
			cleanupInterval = 5 * time.Second
		} else if cleanupInterval > time.Minute {
			cleanupInterval = time.Minute
		}
		stopCleanup := natHandler.StartCleanup(cleanupInterval)
		defer stopCleanup()

		natConn, err := ed2k.RunUDPServer(ed2k.UDPServerConfig{
			Address: cfg.Address,
			Port:    cfg.NAT.Port,
		}, udpMainHandler)
		if err != nil {
			return fmt.Errorf("nat traversal udp server failed: %w", err)
		}
		defer natConn.Close()
		logging.Infof("listening: nat-udp %s:%d", cfg.Address, cfg.NAT.Port)
	}

	udpConn, err := ed2k.RunUDPServer(udpCfg, udpMainHandler)
	if err != nil {
		return fmt.Errorf("udp server failed: %w", err)
	}
	defer udpConn.Close()
	logging.Infof("listening: udp %s:%d", udpCfg.Address, udpCfg.Port)

	if cfg.SupportCrypt {
		tcpCryptCfg := tcpCfg
		tcpCryptCfg.Port = cfg.TCP.PortObfuscated
		udpCryptCfg := udpCfg
		udpCryptCfg.Port = cfg.UDP.PortObfuscated

		lnCrypt, err := ed2k.RunTCPServer(tcpCryptCfg, runtime.TCPHandler(true))
		if err != nil {
			return fmt.Errorf("obfuscated tcp server failed: %w", err)
		}
		defer lnCrypt.Close()
		logging.Infof("listening: tcp-obfuscated %s:%d", tcpCryptCfg.Address, tcpCryptCfg.Port)

		udpConnCrypt, err := ed2k.RunUDPServer(udpCryptCfg, runtime.UDPHandler(true))
		if err != nil {
			return fmt.Errorf("obfuscated udp server failed: %w", err)
		}
		defer udpConnCrypt.Close()
		logging.Infof("listening: udp-obfuscated %s:%d", udpCryptCfg.Address, udpCryptCfg.Port)
	}

	<-ctx.Done()
	logging.Infof("shutdown signal received, stopping")
	return nil
}

func startBackgroundProcess(args []string) (int, error) {
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), backgroundEnvKey+"=1")

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return 0, err
	}
	defer devNull.Close()

	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull

	if err := cmd.Start(); err != nil {
		return 0, err
	}

	return cmd.Process.Pid, nil
}

func filterDaemonArgs(args []string) []string {
	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-daemon" {
			continue
		}
		if arg == "--daemon" {
			continue
		}
		if arg == "-daemon=true" || arg == "--daemon=true" {
			continue
		}
		if arg == "-daemon=false" || arg == "--daemon=false" {
			continue
		}
		filtered = append(filtered, arg)
	}
	return filtered
}

// firstRoutableIP returns the first candidate that is a usable advertised
// address, or "" when none is. The wildcard is not routable: a client that
// receives it has been told nothing.
func firstRoutableIP(candidates ...string) string {
	for _, c := range candidates {
		if c != "" && c != "0.0.0.0" {
			return c
		}
	}
	return ""
}

// serverIdentitySeed picks what the server hash is derived from.
//
// Deriving it from cfg.Address alone meant every deployment that did not set
// `address` computed MD5("0.0.0.0" + port) — the same hash everywhere, so
// servers were not distinguishable by identity at all. The hostname is used when
// no routable IP is known: unlike a random value it is stable across restarts,
// so an unconfigured server keeps one identity instead of presenting a new one
// after every boot.
//
// Two cases it does not cover, neither worth extra machinery: two unconfigured
// servers on the same host and port would still collide (they cannot both bind
// that port anyway), and renaming the machine changes the identity once. Setting
// `address` or `dynIp` is the real fix.
func serverIdentitySeed(advertisedIP, configuredAddress string) string {
	if advertisedIP != "" {
		return advertisedIP
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		logging.Infof("server hash derived from hostname %q: no routable address configured", host)
		return host
	}
	return configuredAddress
}

// seedServers loads the configured peer servers into storage so OP_SERVERLIST can
// advertise them. This is the only caller of Engine.AddServer outside tests — the
// list was permanently empty before. An entry with an unparseable IP is skipped
// with a warning rather than aborting: BuildServerListPacket errors on the first
// bad IP and sendServerList then drops the whole packet, so one typo would silence
// the entire list. Empty config (the default) seeds nothing, unchanged.
func seedServers(store storage.Engine, entries []config.ServerEntry) {
	for _, e := range entries {
		if _, err := ed2k.IPv4ToInt32LE(e.IP); err != nil {
			logging.Warnf("skipping server list entry %q:%d: invalid IPv4", e.IP, e.Port)
			continue
		}
		store.AddServer(storage.Server{IP: e.IP, Port: e.Port})
	}
	if n := store.ServersCount(); n > 0 {
		logging.Infof("advertising %d server(s) in OP_SERVERLIST", n)
	}
}
