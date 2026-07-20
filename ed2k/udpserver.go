package ed2k

import (
	"net"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"enode/logging"
)

type UDPServerConfig struct {
	Address      string
	Port         uint16
	GetSources   bool
	GetFiles     bool
	SupportCrypt bool
	// Workers and QueueSize bound the datagram handler pool. Zero means the
	// defaults below.
	Workers   int
	QueueSize int
}

// A datagram can cost far more to serve than to send: OP_GLOBGETSOURCES packs
// ~87 hashes into 1400 bytes and each one is a separate synchronous storage
// lookup. Unbounded goroutine-per-datagram turned that asymmetry into an
// amplifier, so the pool caps how much work is in flight at once.
const defaultUDPQueueSize = 1024

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

type udpDatagram struct {
	data   []byte
	remote *net.UDPAddr
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

	workers, queueSize := udpPoolSize(cfg)
	jobs := make(chan udpDatagram, queueSize)
	var dropped atomic.Int64

	for i := 0; i < workers; i++ {
		go func() {
			for job := range jobs {
				handler(job.data, job.remote, conn)
			}
		}()
	}

	go func() {
		defer close(jobs)
		buf := make([]byte, 65535)
		lastReport := time.Time{}
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// buf is reused on the next iteration, so the worker must get its own
			// copy — handing it buf[:n] would race the following read.
			data := append([]byte(nil), buf[:n]...)
			logging.Debugf("udp recv remote=%s local=%s len=%d", remote, conn.LocalAddr(), n)

			select {
			case jobs <- udpDatagram{data: data, remote: remote}:
			default:
				// Never block here. Blocking stalls ReadFromUDP, which turns a
				// flood into total UDP unavailability — worse than shedding load.
				total := dropped.Add(1)
				if time.Since(lastReport) >= udpDropReportEvery {
					lastReport = time.Now()
					logging.Warnf("udp queue full, dropping datagrams: total=%d queue=%d workers=%d",
						total, queueSize, workers)
				}
			}
		}
	}()
	return conn, nil
}

const udpDropReportEvery = 10 * time.Second

// udpPoolSize resolves the worker and queue sizes, defaulting the worker count
// from the CPU count. The work is largely storage I/O rather than CPU, so a
// small multiple of NumCPU keeps the database busy without unbounded fan-out.
func udpPoolSize(cfg UDPServerConfig) (workers, queueSize int) {
	workers = cfg.Workers
	if workers <= 0 {
		workers = runtime.NumCPU() * 4
	}
	if workers < 1 {
		workers = 1
	}
	queueSize = cfg.QueueSize
	if queueSize <= 0 {
		queueSize = defaultUDPQueueSize
	}
	return workers, queueSize
}
