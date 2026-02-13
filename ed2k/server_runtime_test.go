package ed2k

import (
	"bytes"
	"encoding/binary"
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

func TestUDPObfuscatedNATRegisterReplyIsEncrypted(t *testing.T) {
	serverKey := uint32(0x22334455)
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{UDPServerKey: serverKey}, storage.NewMemoryEngine())
	nat := NewNATTraversalHandler(time.Minute)
	rt.SetNATHandler(nat)
	handler := rt.UDPHandler(true)

	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen server udp: %v", err)
	}
	defer serverConn.Close()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client udp: %v", err)
	}
	defer clientConn.Close()

	var hash [16]byte
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	req := encodeNATPacket(OpNatRegister, hash[:])
	crypt := NewUDPCrypt(true, serverKey)
	wire := buildObfuscatedClientUDP(crypt, req, 0x3344)

	remote := clientConn.LocalAddr().(*net.UDPAddr)
	handler(wire, remote, serverConn)

	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := clientConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read nat register ack: %v", err)
	}
	gotWire := append([]byte(nil), buf[:n]...)
	if len(gotWire) == 0 {
		t.Fatalf("empty nat register ack")
	}
	if gotWire[0] == PrNat {
		t.Fatalf("nat register ack should be obfuscated on udp-obfuscated listener")
	}

	plain, ok := decryptObfuscatedServerUDP(crypt, gotWire)
	if !ok {
		t.Fatalf("failed to decrypt obfuscated nat register ack")
	}
	opcode, _, ok := decodeNATPacket(plain)
	if !ok {
		t.Fatalf("decrypted ack is not a NAT packet")
	}
	if opcode != OpNatRegister {
		t.Fatalf("opcode=0x%x want=0x%x", opcode, OpNatRegister)
	}
}

func TestUDPPlainNATRegisterReplyIsPlaintext(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{UDPServerKey: 0x22334455}, storage.NewMemoryEngine())
	nat := NewNATTraversalHandler(time.Minute)
	rt.SetNATHandler(nat)
	handler := rt.UDPHandler(false)

	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen server udp: %v", err)
	}
	defer serverConn.Close()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client udp: %v", err)
	}
	defer clientConn.Close()

	var hash [16]byte
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	req := encodeNATPacket(OpNatRegister, hash[:])
	remote := clientConn.LocalAddr().(*net.UDPAddr)
	handler(req, remote, serverConn)

	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := clientConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read nat register ack: %v", err)
	}
	got := append([]byte(nil), buf[:n]...)
	if len(got) == 0 {
		t.Fatalf("empty nat register ack")
	}
	if got[0] != PrNat {
		t.Fatalf("nat register ack should be plaintext on udp listener")
	}

	opcode, _, ok := decodeNATPacket(got)
	if !ok {
		t.Fatalf("ack is not a NAT packet")
	}
	if opcode != OpNatRegister {
		t.Fatalf("opcode=0x%x want=0x%x", opcode, OpNatRegister)
	}
}

func buildObfuscatedClientUDP(crypt *UDPCrypt, plain []byte, randomKey uint16) []byte {
	enc := NewBuffer(len(plain) + 5)
	_ = enc.PutUInt32LE(MagicValueUDPSyncServer)
	_ = enc.PutUInt8(0)
	enc.PutBuffer(plain)
	cipher := RC4Crypt(enc.Bytes(), len(enc.Bytes()), crypt.rc4Key(MagicValueUDPClientServer, randomKey))
	wire := NewBuffer(3 + len(cipher))
	_ = wire.PutUInt8(0xff)
	_ = wire.PutUInt16LE(randomKey)
	wire.PutBuffer(cipher)
	return wire.Bytes()
}

func decryptObfuscatedServerUDP(crypt *UDPCrypt, wire []byte) ([]byte, bool) {
	if len(wire) < 8 {
		return nil, false
	}
	randomKey := binary.LittleEndian.Uint16(wire[1:3])
	dec := RC4Crypt(wire[3:], len(wire)-3, crypt.rc4Key(MagicValueUDPServerClient, randomKey))
	if len(dec) < 5 {
		return nil, false
	}
	sync := binary.LittleEndian.Uint32(dec[:4])
	if sync != MagicValueUDPSyncServer {
		return nil, false
	}
	padLen := int(dec[4])
	if 5+padLen > len(dec) {
		return nil, false
	}
	return dec[5+padLen:], true
}
