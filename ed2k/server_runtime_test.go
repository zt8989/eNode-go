package ed2k

import (
	"bytes"
	"net"
	"testing"
	"time"

	"enode/storage"
)

type mockConn struct {
	closed int
}

func (m *mockConn) Read(_ []byte) (int, error)  { return 0, net.ErrClosed }
func (m *mockConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockConn) Close() error                { m.closed++; return nil }
func (m *mockConn) LocalAddr() net.Addr         { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4661} }
func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 50000}
}
func (m *mockConn) SetDeadline(_ time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(_ time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestReplaceSessionClosesOldConnection(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
	oldConn := &mockConn{}
	newConn := &mockConn{}
	oldClient := &tcpClient{conn: oldConn, remoteHost: "old"}
	newClient := &tcpClient{conn: newConn, remoteHost: "new"}

	rt.replaceSession("h:abc", oldClient)
	rt.replaceSession("h:abc", newClient)

	if oldConn.closed != 1 {
		t.Fatalf("expected old connection closed once, got %d", oldConn.closed)
	}
	if newConn.closed != 0 {
		t.Fatalf("unexpected new connection close count: %d", newConn.closed)
	}
}

func TestLoginSessionKey(t *testing.T) {
	hash := bytes.Repeat([]byte{1}, 16)
	if got := loginSessionKey(hash, 0); got == "" || got[:2] != "h:" {
		t.Fatalf("unexpected hash key: %q", got)
	}
	if got := loginSessionKey(nil, 0x1234); got != "i:00001234" {
		t.Fatalf("unexpected id key: %q", got)
	}
	if got := loginSessionKey(nil, 0); got != "" {
		t.Fatalf("expected empty key, got: %q", got)
	}
}

func TestNewServerRuntimeSetsDefaultServerStatusInterval(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
	if rt.TCP.ServerStatusInterval != defaultServerStatusInterval {
		t.Fatalf("default interval=%v want=%v", rt.TCP.ServerStatusInterval, defaultServerStatusInterval)
	}

	custom := 2 * time.Minute
	rt2 := NewServerRuntime(TCPRuntimeConfig{ServerStatusInterval: custom}, UDPRuntimeConfig{}, storage.NewMemoryEngine())
	if rt2.TCP.ServerStatusInterval != custom {
		t.Fatalf("custom interval=%v want=%v", rt2.TCP.ServerStatusInterval, custom)
	}
}
