package ed2k

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// waitForHandlers blocks until every handler goroutine has returned. A
// WaitGroup cannot be used here: Add would have to run inside the handler,
// which races with Wait.
func waitForHandlers(t *testing.T, live *atomic.Int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for live.Load() > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d handler goroutines still running", live.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// dialAndHold opens a connection and keeps it open until release is closed, so
// the server-side handler stays resident and the connection counts against the
// limit. It reports whether the server kept the connection open.
func dialAndHold(t *testing.T, addr string, release <-chan struct{}, wg *sync.WaitGroup) bool {
	t.Helper()
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	// A refused connection is accepted at the TCP layer and then closed, so the
	// distinguishing signal is EOF on the first read, not a dial error.
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	kept := err != nil && !isEOFish(err)
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-release
		_ = conn.Close()
	}()
	return kept
}

func isEOFish(err error) bool {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return false
	}
	return true
}

func TestRunTCPServerEnforcesMaxConnections(t *testing.T) {
	const limit = 2
	handlerRelease := make(chan struct{})
	var liveHandlers atomic.Int64

	ln, err := RunTCPServer(TCPServerConfig{Address: "127.0.0.1", Port: 0, MaxConnections: limit},
		func(conn net.Conn) {
			liveHandlers.Add(1)
			defer liveHandlers.Add(-1)
			<-handlerRelease
			_ = conn.Close()
		})
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	t.Logf("input: maxConnections=%d listening on %s", limit, addr)

	release := make(chan struct{})
	var dialWG sync.WaitGroup
	defer func() {
		close(release)
		close(handlerRelease)
		dialWG.Wait()
		waitForHandlers(t, &liveHandlers)
	}()

	var kept []bool
	for i := 0; i < limit+1; i++ {
		k := dialAndHold(t, addr, release, &dialWG)
		kept = append(kept, k)
		t.Logf("output: connection %d kept=%t", i+1, k)
	}

	for i := 0; i < limit; i++ {
		if !kept[i] {
			t.Fatalf("connection %d was within the limit but was closed", i+1)
		}
	}
	if kept[limit] {
		t.Fatalf("connection %d exceeded maxConnections=%d but was kept open", limit+1, limit)
	}
}

// Zero must mean unlimited, not "refuse everything": setDefaults never populates
// MaxConnections, so every config that omits the key arrives here as zero.
func TestRunTCPServerZeroMaxConnectionsIsUnlimited(t *testing.T) {
	handlerRelease := make(chan struct{})
	var liveHandlers atomic.Int64

	ln, err := RunTCPServer(TCPServerConfig{Address: "127.0.0.1", Port: 0, MaxConnections: 0},
		func(conn net.Conn) {
			liveHandlers.Add(1)
			defer liveHandlers.Add(-1)
			<-handlerRelease
			_ = conn.Close()
		})
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	t.Logf("input: maxConnections=0 listening on %s", addr)

	release := make(chan struct{})
	var dialWG sync.WaitGroup
	defer func() {
		close(release)
		close(handlerRelease)
		dialWG.Wait()
		waitForHandlers(t, &liveHandlers)
	}()

	const n = 5
	for i := 0; i < n; i++ {
		if !dialAndHold(t, addr, release, &dialWG) {
			t.Fatalf("connection %d was refused with maxConnections=0", i+1)
		}
	}
	t.Logf("output: all %d connections kept open", n)
}

// Slots must be returned when handlers finish. Without the decrement the server
// would accept exactly MaxConnections connections in its lifetime, then go deaf
// — a slower but more total failure than never limiting at all.
func TestRunTCPServerReleasesSlots(t *testing.T) {
	const limit = 1
	served := make(chan struct{}, 8)

	ln, err := RunTCPServer(TCPServerConfig{Address: "127.0.0.1", Port: 0, MaxConnections: limit},
		func(conn net.Conn) {
			served <- struct{}{}
			_ = conn.Close()
		})
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	const rounds = 3
	t.Logf("input: maxConnections=%d, %d sequential connections", limit, rounds)

	for i := 0; i < rounds; i++ {
		conn, err := net.Dial("tcp4", addr)
		if err != nil {
			t.Fatalf("connection %d failed to dial: %v", i+1, err)
		}
		select {
		case <-served:
			t.Logf("output: connection %d reached the handler", i+1)
		case <-time.After(2 * time.Second):
			t.Fatalf("connection %d never reached the handler: slot was not released", i+1)
		}
		_ = conn.Close()
	}
}
