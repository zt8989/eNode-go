package ed2k

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"enode/storage"
)

// tcpClientProbe wires a tcpClient to one end of a socket pair and returns a
// reader for whatever the server writes back.
func tcpClientProbe(t *testing.T, engine storage.Engine) (*tcpClient, func() []byte) {
	t.Helper()

	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })

	rt := NewServerRuntime(TCPRuntimeConfig{Hash: []byte("0123456789abcdef")}, UDPRuntimeConfig{}, engine)
	c := newTCPClient(rt, server, false)

	replies := make(chan []byte, 4)
	go func() {
		buf := make([]byte, 65536)
		for {
			_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := client.Read(buf)
			if err != nil {
				close(replies)
				return
			}
			replies <- append([]byte(nil), buf[:n]...)
		}
	}()

	return c, func() []byte {
		select {
		case r, ok := <-replies:
			if !ok {
				return nil
			}
			return r
		case <-time.After(500 * time.Millisecond):
			return nil
		}
	}
}

// A search matching nothing used to send nothing at all. OP_SEARCHRESULT is the
// only packet that reaches eMule's LocalEd2kSearchEnd, which cancels the 50 s
// local-search timer — so on silence the user's client sits in "Searching…" for
// the full timeout and then cancels without ever displaying "0 results".
func TestSearchRequestRepliesWhenNothingMatches(t *testing.T) {
	c, nextReply := tcpClientProbe(t, storage.NewMemoryEngine())

	// A plain text search for a term no file matches.
	payload := []byte{0x01, 0x07, 0x00, 'n', 'o', 't', 'h', 'i', 'n', 'g'}
	t.Logf("input: OP_SEARCHREQUEST for \"nothing\" against an empty store")

	go c.handleSearchRequest(NewBufferFromBytes(payload))

	reply := nextReply()
	t.Logf("output: reply=% x", reply)

	if reply == nil {
		t.Fatal("no reply sent — the client would stall for its full 50 s search timeout")
	}
	// protocol(1) size(4) opcode(1) count(4)
	if len(reply) < 10 {
		t.Fatalf("reply is only %d bytes: % x", len(reply), reply)
	}
	if reply[0] != PrED2K {
		t.Fatalf("protocol byte is 0x%02x, want 0x%02x", reply[0], PrED2K)
	}
	if reply[5] != OpSearchResult {
		t.Fatalf("opcode is 0x%02x, want OP_SEARCHRESULT 0x%02x", reply[5], OpSearchResult)
	}
	if count := binary.LittleEndian.Uint32(reply[6:10]); count != 0 {
		t.Fatalf("result count is %d, want 0", count)
	}
	t.Logf("output: OP_SEARCHRESULT with a zero count, which stops the client's timer")
}

// The same for OP_FOUNDSOURCES. This one fixes no stall — eMule has no timeout
// on source replies — but it keeps the two TCP paths symmetrical, matching the
// original's unconditional send.
func TestGetSourcesRepliesWhenNoSourcesKnown(t *testing.T) {
	c, nextReply := tcpClientProbe(t, storage.NewMemoryEngine())

	// hash(16) + size(4); a non-zero size avoids the 64-bit large-file branch.
	payload := append([]byte("fedcba9876543210"), 0x00, 0x04, 0x00, 0x00)
	t.Logf("input: OP_GETSOURCES for a hash with no sources, size=1024")

	go c.handleGetSources(NewBufferFromBytes(payload), false)

	reply := nextReply()
	t.Logf("output: reply=% x", reply)

	if reply == nil {
		t.Fatal("no reply sent for an unknown hash")
	}
	if reply[5] != OpFoundSources {
		t.Fatalf("opcode is 0x%02x, want OP_FOUNDSOURCES 0x%02x", reply[5], OpFoundSources)
	}
	// protocol(1) size(4) opcode(1) hash(16) count(1)
	if got := reply[22]; got != 0 {
		t.Fatalf("source count is %d, want 0", got)
	}
}

// The UDP paths must NOT be changed. Their empty-result guards sit inside loops
// over a multi-hash request, so replying unconditionally would emit one datagram
// per unknown hash — turning a single 200-hash OP_GLOBGETSOURCES into a
// 200-datagram reflection, which is exactly what the getSources gate exists to
// prevent.
func TestUDPGetSourcesStaysSilentForUnknownHashes(t *testing.T) {
	request := []byte{PrED2K, OpGlobGetSources}
	for i := 0; i < 3; i++ {
		hash := make([]byte, 16)
		hash[0] = byte(i + 1)
		request = append(request, hash...)
	}
	t.Logf("input: OP_GLOBGETSOURCES batching 3 unknown hashes, getSources enabled")

	reply := gateProbe(t, UDPRuntimeConfig{GetSources: true}, request)
	t.Logf("output: reply=%d bytes", len(reply))

	if reply != nil {
		t.Fatalf("replied with %d bytes to unknown hashes — one datagram per hash is an amplification vector", len(reply))
	}
}
