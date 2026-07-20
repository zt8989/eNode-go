package ed2k

import (
	"net"
	"testing"
	"time"

	"enode/storage"
)

// searchSpy counts how many queries actually reach storage, which is what
// distinguishes "parsed garbage and ran it" from "refused to parse".
type searchSpy struct {
	storage.Engine
	searches int
}

func (s *searchSpy) FindBySearch(expr *storage.SearchExpr) []storage.File {
	s.searches++
	return s.Engine.FindBySearch(expr)
}

// seededEngine holds one file named "food.bin", so a search for "food" that
// does get executed produces an observable reply.
func seededEngine(t *testing.T) storage.Engine {
	t.Helper()
	engine := storage.NewMemoryEngine()
	owner := storage.ClientInfo{Hash: []byte("0123456789abcdef"), ID: 0x0100007F, Port: 4662}
	engine.Connect(owner)
	engine.AddFile(storage.File{
		Hash: []byte("fedcba9876543210"),
		Size: 1024,
		Name: "food.bin",
	}, owner)
	return engine
}

// udpProbe returns a server socket to hand the handler and a client socket to
// watch for replies, plus a helper that reports whether anything was sent.
func udpProbe(t *testing.T) (server *net.UDPConn, remote *net.UDPAddr, gotReply func() []byte) {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen server udp: %v", err)
	}
	t.Cleanup(func() { server.Close() })

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client udp: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	return server, client.LocalAddr().(*net.UDPAddr), func() []byte {
		_ = client.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		buf := make([]byte, 4096)
		n, _, err := client.ReadFromUDP(buf)
		if err != nil {
			return nil
		}
		return append([]byte(nil), buf[:n]...)
	}
}

// OP_GLOBSEARCHREQ3 carries a mandatory tag block before the search expression.
// GetTags aborts mid-loop on a malformed tag without rewinding, so discarding
// its error left the read pointer inside a half-consumed tag — and the parser
// then built a search expression out of tag payload bytes and ran it against
// the database. Unauthenticated, over UDP, with no handshake.
func TestGlobSearchReq3StopsOnMalformedTags(t *testing.T) {
	spy := &searchSpy{Engine: seededEngine(t)}
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{}, spy)
	server, remote, gotReply := udpProbe(t)

	// The tag block is built so that GetTags fails with the read pointer landing
	// exactly on a *valid* search expression. That is the dangerous case: a
	// discarded error there means the parser reads a well-formed query out of
	// what is really tag payload, and the server executes it.
	//
	// Tag 2 is long-format (no 0x80 bit) declaring a name length of 2, which
	// GetTag rejects because the name must be exactly 1 byte — after consuming
	// the type byte and the 2-byte length, i.e. 3 bytes exactly.
	payload := []byte{
		0x02, 0x00, 0x00, 0x00, // tag count = 2
		0x90, 0x01, // tag 1: valid short-format, zero-length string
		0x05, 0x02, 0x00, // tag 2: long format, bad name length -> fails here
	}
	payload = append(payload, 0x01, 0x04, 0x00, 'f', 'o', 'o', 'd') // text search "food"

	b := NewBufferFromBytes(payload)
	t.Logf("input: % x", payload)

	rt.udpGlobSearchReq3(b, remote, server, nil, "udp")

	reply := gotReply()
	t.Logf("output: searches executed=%d reply=%d bytes", spy.searches, len(reply))

	// The point is not merely that no reply went out — it is that no query was
	// built at all. Whether the leftover bytes happen to parse into something
	// executable depends on the exact garbage, so counting FindBySearch is the
	// stable discriminator; asserting only on the reply would let a run where
	// the garbage query returned no rows pass as if it were fixed.
	if spy.searches != 0 {
		t.Fatalf("ran %d search(es) built from a malformed tag block", spy.searches)
	}
	if reply != nil {
		t.Fatalf("a malformed tag block still produced a %d-byte reply", len(reply))
	}
}

// The tag block is legitimate protocol, not padding: eMule writes a tag count
// and at least one tag before the expression. A well-formed request must still
// search, or this fix would silently disable OP_GLOBSEARCHREQ3 entirely.
func TestGlobSearchReq3AcceptsWellFormedTags(t *testing.T) {
	rt := NewServerRuntime(TCPRuntimeConfig{}, UDPRuntimeConfig{}, seededEngine(t))
	server, remote, gotReply := udpProbe(t)

	payload := []byte{
		0x01, 0x00, 0x00, 0x00, // tag count = 1
		0x90, 0x01, // one valid short-format tag
		0x01, 0x04, 0x00, 'f', 'o', 'o', 'd', // text term "food"
	}
	t.Logf("input: % x", payload)

	rt.udpGlobSearchReq3(NewBufferFromBytes(payload), remote, server, nil, "udp")

	reply := gotReply()
	t.Logf("output: reply=%d bytes", len(reply))
	if reply == nil {
		t.Fatal("a well-formed search request produced no reply")
	}
}
