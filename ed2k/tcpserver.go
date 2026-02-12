package ed2k

import (
	"net"
	"strconv"

	"enode/logging"
)

type TCPServerConfig struct {
	Address        string
	Port           uint16
	MaxConnections int
	AuxiliarPort   bool
	RequireCrypt   bool
	RequestCrypt   bool
	SupportCrypt   bool
	IPInLogin      bool
}

func BuildTCPFlags(cfg TCPServerConfig) uint32 {
	flags := FlagZlib + FlagNewTags + FlagUnicode + FlagLargeFiles
	if cfg.AuxiliarPort {
		flags += FlagAuxPort
	}
	if cfg.RequireCrypt {
		flags += FlagRequireCrypt
	}
	if cfg.RequestCrypt {
		flags += FlagRequestCrypt
	}
	if cfg.SupportCrypt {
		flags += FlagSupportCrypt
	}
	if cfg.IPInLogin {
		flags += FlagIPInLogin
	}
	return flags
}

func RunTCPServer(cfg TCPServerConfig, handler func(net.Conn)) (net.Listener, error) {
	addr := net.JoinHostPort(cfg.Address, strconv.Itoa(int(cfg.Port)))
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				logging.Debugf("tcp accept remote=%s local=%s", conn.RemoteAddr(), conn.LocalAddr())
				handler(conn)
			}()
		}
	}()
	return ln, nil
}
