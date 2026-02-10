package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"enode/config"
	"enode/ed2k"
	"enode/logging"
	"enode/storage"
)

func main() {
	configPath := flag.String("config", "enode.config.yaml", "path to YAML config")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}
	if err := logging.SetOutputFile(cfg.LogFile); err != nil {
		log.Fatalf("config logFile invalid: %v", err)
	}
	if err := logging.SetLevelFromString(cfg.LogLevel); err != nil {
		log.Fatalf("config logLevel invalid: %v", err)
	}
	logging.Infof("welcome: enode starting (config=%s)", *configPath)

	engine, err := storage.NewEngine(cfg.StorageEngineConfig())
	if err != nil {
		logging.Fatalf("storage engine create failed: %v", err)
	}
	if err := engine.Init(); err != nil {
		logging.Fatalf("storage init failed: %v", err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			logging.Warnf("storage close error: %v", err)
		}
	}()

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
	serverHash := ed2k.MD5([]byte(fmt.Sprintf("%s%d", cfg.Address, cfg.TCP.Port)))

	runtime := ed2k.NewServerRuntime(
		ed2k.TCPRuntimeConfig{
			Name:              cfg.Name,
			Description:       cfg.Description,
			Address:           cfg.Address,
			Port:              cfg.TCP.Port,
			Flags:             tcpFlags,
			Hash:              serverHash,
			MessageLogin:      cfg.MessageLogin,
			MessageLowID:      cfg.MessageLowID,
			ConnectionTimeout: time.Duration(cfg.TCP.ConnectionTimeout) * time.Millisecond,
			DisconnectTimeout: time.Duration(cfg.TCP.DisconnectTimeout) * time.Second,
			AllowLowIDs:       cfg.TCP.AllowLowIDs,
			SupportCrypt:      cfg.SupportCrypt,
		},
		ed2k.UDPRuntimeConfig{
			Name:           cfg.Name,
			Description:    cfg.Description,
			DynIP:          cfg.DynIP,
			UDPFlags:       udpFlags,
			UDPPortObf:     cfg.UDP.PortObfuscated,
			TCPPortObf:     cfg.TCP.PortObfuscated,
			UDPServerKey:   cfg.UDP.ServerKey,
			MaxConnections: uint32(cfg.TCP.MaxConnections),
		},
		engine,
	)

	ln, err := ed2k.RunTCPServer(tcpCfg, runtime.TCPHandler(false))
	if err != nil {
		logging.Fatalf("tcp server failed: %v", err)
	}
	defer ln.Close()
	logging.Infof("listening: tcp %s:%d", tcpCfg.Address, tcpCfg.Port)

	udpHandler := runtime.UDPHandler(false)
	udpMainHandler := udpHandler
	if cfg.NAT.Enabled {
		natTTL := time.Duration(cfg.NAT.RegistrationTTLSeconds) * time.Second
		natHandler := ed2k.NewNATTraversalHandler(natTTL)
		natHandler.ConfigureRegisterEndpointFromConfig(cfg.DynIP, cfg.Address, cfg.UDP.Port)
		udpMainHandler = func(data []byte, remote *net.UDPAddr, conn *net.UDPConn) {
			if len(data) > 0 && data[0] == ed2k.PrNat {
				natHandler.HandlePacket(data, remote, conn)
				return
			}
			udpHandler(data, remote, conn)
		}
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
			logging.Fatalf("nat traversal udp server failed: %v", err)
		}
		defer natConn.Close()
		logging.Infof("listening: nat-udp %s:%d", cfg.Address, cfg.NAT.Port)
	}

	udpConn, err := ed2k.RunUDPServer(udpCfg, udpMainHandler)
	if err != nil {
		logging.Fatalf("udp server failed: %v", err)
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
			logging.Fatalf("obfuscated tcp server failed: %v", err)
		}
		defer lnCrypt.Close()
		logging.Infof("listening: tcp-obfuscated %s:%d", tcpCryptCfg.Address, tcpCryptCfg.Port)

		udpConnCrypt, err := ed2k.RunUDPServer(udpCryptCfg, runtime.UDPHandler(true))
		if err != nil {
			logging.Fatalf("obfuscated udp server failed: %v", err)
		}
		defer udpConnCrypt.Close()
		logging.Infof("listening: udp-obfuscated %s:%d", udpCryptCfg.Address, udpCryptCfg.Port)
	}

	select {}
}
