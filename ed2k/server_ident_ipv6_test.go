package ed2k

import (
	"bytes"
	"testing"
)

// TestServerIdentAdvertisesIPv6 checks the CT_MOD_SVR_IP_V6 (0xaf) hash tag is
// appended to OP_SERVERIDENT when the server has a public IPv6, and omitted
// otherwise.
func TestServerIdentAdvertisesIPv6(t *testing.T) {
	serverV6 := []byte{0x26, 0x06, 0x47, 0, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11}
	conf := ServerConfig{
		Name:        "eNode",
		Description: "test",
		Address:     "192.0.2.1",
		Hash:        bytes.Repeat([]byte{0x01}, 16),
		TCPPort:     5555,
		IPv6:        serverV6,
	}
	buf, err := BuildServerIdentPacket(conf)
	if err != nil {
		t.Fatal(err)
	}
	tags := parseServerIdentTags(t, buf)
	got, ok := tags["svripv6"]
	if !ok {
		t.Fatal("CT_MOD_SVR_IP_V6 tag missing")
	}
	if b, ok := got.([]byte); !ok || !bytes.Equal(b, serverV6) {
		t.Fatalf("server IPv6 tag mismatch: %x", got)
	}
	t.Logf("OP_SERVERIDENT carries svripv6=%x", serverV6)

	// Without an IPv6, the tag must be absent (no regression for v4-only servers).
	conf.IPv6 = nil
	buf2, err := BuildServerIdentPacket(conf)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parseServerIdentTags(t, buf2)["svripv6"]; ok {
		t.Fatal("svripv6 tag present on a server with no IPv6")
	}
	t.Log("v4-only server omits the svripv6 tag")
}

// parseServerIdentTags decodes an OP_SERVERIDENT packet's tag list to a
// name->value map.
func parseServerIdentTags(t *testing.T, buf *Buffer) map[string]any {
	t.Helper()
	opcode, payload := tcpFoundSourcesPayload(t, buf)
	if opcode != OpServerIdent {
		t.Fatalf("opcode = 0x%02x, want OP_SERVERIDENT", opcode)
	}
	b := NewBufferFromBytes(payload)
	_ = b.Get(16) // server hash
	_, _ = b.GetUInt32LE()
	_, _ = b.GetUInt16LE()
	tags, err := b.GetTags()
	if err != nil {
		t.Fatalf("tag decode: %v", err)
	}
	out := make(map[string]any, len(tags))
	for _, tg := range tags {
		out[tg.Name] = tg.Value
	}
	return out
}
