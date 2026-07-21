package ed2k

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"enode/storage"
)

// TestGetSourcesSentinelGatedByServerIPv6 drives OP_GETSOURCES end-to-end through
// a tcpClient and asserts the sentinel is emitted only when the server has IPv6
// enabled. Even a session that advertised v6 capability gets the byte-identical
// classic layout from an IPv6-disabled server.
func TestGetSourcesSentinelGatedByServerIPv6(t *testing.T) {
	hash := bytes.Repeat([]byte{0xaa}, 16)
	ipv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09}
	const fileSize = 100

	for _, serverV6 := range []bool{true, false} {
		engine := storage.NewMemoryEngine()
		// A v6-only source: LowID id, reachable IPv6, no HighID.
		engine.AddFile(
			storage.File{Hash: hash, Name: "x.bin", Size: fileSize},
			storage.ClientInfo{ID: 12345, Port: 4662, Hash: bytes.Repeat([]byte{0x11}, 16), IPv6: ipv6, IPv6Reachable: true},
		)
		rt := NewServerRuntime(TCPRuntimeConfig{IPv6: serverV6, PublishV6Sources: serverV6}, UDPRuntimeConfig{}, engine)

		srvConn, cliConn := net.Pipe()
		c := newTCPClient(rt, srvConn, false)
		c.ipv6Capable = true // pretend the client sent CT_MOD_IP_V6

		// OP_GETSOURCES payload: hash(16) + size(4).
		payload := make([]byte, 20)
		copy(payload, hash)
		binary.LittleEndian.PutUint32(payload[16:], fileSize)

		go func() {
			c.handleGetSources(NewBufferFromBytes(payload), false)
			_ = srvConn.Close()
		}()

		_ = cliConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		raw, _ := io.ReadAll(cliConn)
		_ = cliConn.Close()

		if len(raw) < 6 || raw[0] != PrED2K || raw[5] != OpFoundSources {
			t.Fatalf("serverV6=%v: unexpected reply framing: % x", serverV6, raw)
		}
		// payload after opcode: hash(16) + count(1) + id(4) + port(2) [+ ipv6(16)]
		body := raw[6:]
		id := binary.LittleEndian.Uint32(body[17:21])
		hasSentinel := id == SentinelIPv6ID

		if serverV6 && !hasSentinel {
			t.Fatalf("IPv6-enabled server should emit the sentinel, got id=0x%08x", id)
		}
		if !serverV6 && hasSentinel {
			t.Fatalf("IPv6-disabled server leaked a sentinel to a capable session")
		}
		t.Logf("serverV6=%v -> id=0x%08x sentinel=%v len=%d", serverV6, id, hasSentinel, len(raw))
	}
}
