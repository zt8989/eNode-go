package ed2k

import (
	"net"
	"strconv"

	"enode/logging"
)

type UDPServerConfig struct {
	Address      string
	Port         uint16
	GetSources   bool
	GetFiles     bool
	SupportCrypt bool
}

func BuildUDPFlags(cfg UDPServerConfig) uint32 {
	flags := FlagNewTags + FlagUnicode + FlagLargeFiles
	if cfg.GetSources {
		flags += FlagUdpExtSources + FlagUdpExtSrc2
	}
	if cfg.GetFiles {
		flags += FlagUdpExtFiles
	}
	if cfg.SupportCrypt {
		flags += FlagUdpObfusc + FlagTcpObfusc
	}
	return flags
}

func RunUDPServer(cfg UDPServerConfig, handler func([]byte, *net.UDPAddr, *net.UDPConn)) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(cfg.Address, strconv.Itoa(int(cfg.Port))))
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			data := append([]byte(nil), buf[:n]...)
			logging.Debugf("udp recv remote=%s local=%s len=%d", remote, conn.LocalAddr(), n)
			go handler(data, remote, conn)
		}
	}()
	return conn, nil
}
