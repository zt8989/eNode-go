package main

import (
	"flag"
	"log"
	"net"

	"enode/config"
	"enode/ed2k"
	"enode/storage"
)

func main() {
	configPath := flag.String("config", "enode.config.yaml", "path to YAML config")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}

	engine, err := storage.NewEngine(cfg.StorageEngineConfig())
	if err != nil {
		log.Fatalf("storage engine create failed: %v", err)
	}
	if err := engine.Init(); err != nil {
		log.Fatalf("storage init failed: %v", err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			log.Printf("storage close error: %v", err)
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

	ln, err := ed2k.RunTCPServer(tcpCfg, func(_ net.Conn) {})
	if err != nil {
		log.Fatalf("tcp server failed: %v", err)
	}
	defer ln.Close()

	udpConn, err := ed2k.RunUDPServer(udpCfg, func([]byte, *net.UDPAddr, *net.UDPConn) {})
	if err != nil {
		log.Fatalf("udp server failed: %v", err)
	}
	defer udpConn.Close()

	if cfg.SupportCrypt {
		tcpCryptCfg := tcpCfg
		tcpCryptCfg.Port = cfg.TCP.PortObfuscated
		udpCryptCfg := udpCfg
		udpCryptCfg.Port = cfg.UDP.PortObfuscated

		lnCrypt, err := ed2k.RunTCPServer(tcpCryptCfg, func(_ net.Conn) {})
		if err != nil {
			log.Fatalf("obfuscated tcp server failed: %v", err)
		}
		defer lnCrypt.Close()

		udpConnCrypt, err := ed2k.RunUDPServer(udpCryptCfg, func([]byte, *net.UDPAddr, *net.UDPConn) {})
		if err != nil {
			log.Fatalf("obfuscated udp server failed: %v", err)
		}
		defer udpConnCrypt.Close()
	}

	select {}
}
