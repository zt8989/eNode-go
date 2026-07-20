package ed2k

import (
	"net"
	"strconv"
	"sync/atomic"

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

// RunTCPServer accepts connections until the listener is closed, enforcing
// cfg.MaxConnections.
//
// A non-positive MaxConnections means unlimited. That is deliberate rather than
// defensive: config.setDefaults leaves the field at zero when the YAML omits it,
// so treating zero as a limit would refuse every connection on a default config.
func RunTCPServer(cfg TCPServerConfig, handler func(net.Conn)) (net.Listener, error) {
	addr := net.JoinHostPort(cfg.Address, strconv.Itoa(int(cfg.Port)))
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, err
	}
	var active atomic.Int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if cfg.MaxConnections > 0 && active.Add(1) > int64(cfg.MaxConnections) {
				active.Add(-1)
				logging.Warnf("tcp connection refused remote=%s: at maxConnections=%d",
					conn.RemoteAddr(), cfg.MaxConnections)
				_ = conn.Close()
				continue
			}
			go func() {
				if cfg.MaxConnections > 0 {
					defer active.Add(-1)
				}
				logging.Debugf("tcp accept remote=%s local=%s", conn.RemoteAddr(), conn.LocalAddr())
				handler(conn)
			}()
		}
	}()
	return ln, nil
}
