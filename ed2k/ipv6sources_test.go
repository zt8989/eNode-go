package ed2k

import (
	"bytes"
	"encoding/binary"
	"testing"

	"enode/storage"
)

var testFileHash = bytes.Repeat([]byte{0xaa}, 16)

func v6(b byte) []byte {
	ip := make([]byte, 16)
	ip[0], ip[1], ip[15] = 0x20, 0x01, b
	return ip
}

// tcpFoundSourcesPayload strips the PR_ED2K header (proto + size) and returns the
// payload after the opcode byte, plus the opcode.
func tcpFoundSourcesPayload(t *testing.T, buf *Buffer) (opcode byte, payload []byte) {
	t.Helper()
	raw := buf.Bytes()
	if len(raw) < 6 || raw[0] != PrED2K {
		t.Fatalf("not a PR_ED2K packet: % x", raw)
	}
	size := binary.LittleEndian.Uint32(raw[1:5])
	if int(size)+5 != len(raw) {
		t.Fatalf("size mismatch: header=%d actual=%d", size, len(raw)-5)
	}
	return raw[5], raw[6:]
}

// TestClassicFoundSourcesByteIdentical is the backward-compatibility gate: a
// v4-only source must produce exactly the pre-IPv6 bytes.
func TestClassicFoundSourcesByteIdentical(t *testing.T) {
	sources := []storage.Source{{ID: 0x04030201, Port: 4662}}
	buf, err := BuildFoundSourcesPacket(testFileHash, sources)
	if err != nil {
		t.Fatal(err)
	}
	opcode, payload := tcpFoundSourcesPayload(t, buf)
	if opcode != OpFoundSources {
		t.Fatalf("opcode = 0x%02x, want OP_FOUNDSOURCES", opcode)
	}
	// hash(16) + count(1)=1 + id(4) + port(2)
	want := append(append([]byte(nil), testFileHash...), 0x01, 0x01, 0x02, 0x03, 0x04, 0x36, 0x12)
	if !bytes.Equal(payload, want) {
		t.Fatalf("classic bytes changed:\n got % x\nwant % x", payload, want)
	}
	t.Logf("classic v4 source bytes unchanged: % x", payload)
}

// TestSentinelForV6OnlySource: a LowID source with a reachable IPv6 and no HighID
// is published as 0xFFFFFFFF + port + 16 bytes.
func TestSentinelForV6OnlySource(t *testing.T) {
	ip := v6(0x11)
	sources := []storage.Source{{ID: 12345, Port: 4662, IPv6: ip, IPv6Reachable: true}}
	buf, err := BuildFoundSourcesSentinelPacket(testFileHash, sources, false)
	if err != nil {
		t.Fatal(err)
	}
	_, payload := tcpFoundSourcesPayload(t, buf)
	// hash(16) + count(1) + id(4)=FFFFFFFF + port(2) + ipv6(16)
	rest := payload[16:]
	if rest[0] != 1 {
		t.Fatalf("count = %d, want 1", rest[0])
	}
	id := binary.LittleEndian.Uint32(rest[1:5])
	if id != SentinelIPv6ID {
		t.Fatalf("id = 0x%08x, want sentinel 0xffffffff", id)
	}
	if got := rest[7:23]; !bytes.Equal(got, ip) {
		t.Fatalf("ipv6 mismatch: got % x want % x", got, ip)
	}
	if len(rest) != 1+4+2+16 {
		t.Fatalf("unexpected trailing bytes: %d", len(rest))
	}
	t.Logf("v6-only source -> sentinel entry: % x", rest)
}

// TestSentinelObfuPlacesIPv6AfterCryptFields verifies the 16 bytes come after the
// obfuscation byte and user hash, matching eMuleAI's AddSources read order.
func TestSentinelObfuPlacesIPv6AfterCryptFields(t *testing.T) {
	ip := v6(0x22)
	userHash := bytes.Repeat([]byte{0x55}, 16)
	sources := []storage.Source{{
		ID: 999, Port: 5000, UserHash: userHash, CryptOptions: 0x01,
		IPv6: ip, IPv6Reachable: true,
	}}
	buf, err := BuildFoundSourcesSentinelPacket(testFileHash, sources, true)
	if err != nil {
		t.Fatal(err)
	}
	opcode, payload := tcpFoundSourcesPayload(t, buf)
	if opcode != OpFoundSourcesObfu {
		t.Fatalf("opcode = 0x%02x, want OP_FOUNDSOURCES_OBFU", opcode)
	}
	rest := payload[16:] // after fileHash
	// count(1) id(4) port(2) obf(1) userHash(16) ipv6(16)
	obf := rest[7]
	if obf&0x80 == 0 || obf&0x01 == 0 {
		t.Fatalf("obf byte = 0x%02x, want 0x81", obf)
	}
	if !bytes.Equal(rest[8:24], userHash) {
		t.Fatalf("user hash mismatch")
	}
	if !bytes.Equal(rest[24:40], ip) {
		t.Fatalf("ipv6 must follow crypt fields: got % x", rest[24:40])
	}
	t.Logf("obfu sentinel order id,port,obf,hash,ipv6 verified: % x", rest)
}

// TestHighIDSourceWithV6StaysClassic: a source with a routable HighID keeps its
// v4 form even in sentinel mode — direct IPv4 is preferred over the sentinel.
func TestHighIDSourceWithV6StaysClassic(t *testing.T) {
	sources := []storage.Source{{ID: 0x04030201, Port: 4662, IPv6: v6(0x33), IPv6Reachable: true}}
	buf, err := BuildFoundSourcesSentinelPacket(testFileHash, sources, false)
	if err != nil {
		t.Fatal(err)
	}
	_, payload := tcpFoundSourcesPayload(t, buf)
	rest := payload[16:]
	id := binary.LittleEndian.Uint32(rest[1:5])
	if id != 0x04030201 {
		t.Fatalf("HighID source should keep its v4 id, got 0x%08x", id)
	}
	if len(rest) != 1+4+2 {
		t.Fatalf("HighID source should have no trailing IPv6, got %d bytes", len(rest))
	}
	t.Logf("HighID+v6 source stays classic v4: % x", rest)
}

// TestClassicModeNeverEmitsSentinel is the load-bearing safety assertion: even a
// v6-only source is sent in classic form when the format is FormatClassic.
func TestClassicModeNeverEmitsSentinel(t *testing.T) {
	sources := []storage.Source{{ID: 12345, Port: 4662, IPv6: v6(0x44), IPv6Reachable: true}}
	buf, err := BuildFoundSourcesPacket(testFileHash, sources)
	if err != nil {
		t.Fatal(err)
	}
	_, payload := tcpFoundSourcesPayload(t, buf)
	rest := payload[16:]
	if id := binary.LittleEndian.Uint32(rest[1:5]); id == SentinelIPv6ID {
		t.Fatal("classic mode leaked a sentinel entry")
	}
	if len(rest) != 1+4+2 {
		t.Fatalf("classic mode emitted trailing IPv6: %d bytes", len(rest))
	}
	t.Logf("classic mode kept v6-only source as plain LowID entry: % x", rest)
}

// TestUnreachableV6NotPublished: an IPv6 that failed the reachability probe is
// never sent as a sentinel, even in sentinel mode.
func TestUnreachableV6NotPublished(t *testing.T) {
	sources := []storage.Source{{ID: 12345, Port: 4662, IPv6: v6(0x55), IPv6Reachable: false}}
	buf, err := BuildFoundSourcesSentinelPacket(testFileHash, sources, false)
	if err != nil {
		t.Fatal(err)
	}
	_, payload := tcpFoundSourcesPayload(t, buf)
	rest := payload[16:]
	if id := binary.LittleEndian.Uint32(rest[1:5]); id == SentinelIPv6ID {
		t.Fatal("unreachable v6 was published as sentinel")
	}
	t.Logf("unreachable v6 not published: % x", rest)
}

// TestTagBlockFormat: OP_FOUNDSOURCES_IPV6 emits id/port/tagCount/tags; a v6
// source carries one CT_MOD_IP_V6 tag, a v4-only source carries tagCount 0.
func TestTagBlockFormat(t *testing.T) {
	ip := v6(0x66)
	sources := []storage.Source{
		{ID: 12345, Port: 4662, IPv6: ip, IPv6Reachable: true}, // v6-only
		{ID: 0x04030201, Port: 5000},                           // v4-only
	}
	buf, err := BuildFoundSourcesIPv6Packet(testFileHash, sources)
	if err != nil {
		t.Fatal(err)
	}
	opcode, payload := tcpFoundSourcesPayload(t, buf)
	if opcode != OpFoundSourcesIPv6 {
		t.Fatalf("opcode = 0x%02x, want OP_FOUNDSOURCES_IPV6 (0x25)", opcode)
	}
	b := NewBufferFromBytes(payload)
	_ = b.Get(16) // fileHash
	count, _ := b.GetUInt8()
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}
	// source 1: sentinel id + 1 tag (ipv6)
	id1, _ := b.GetUInt32LE()
	_, _ = b.GetUInt16LE()
	tc1, _ := b.GetUInt8()
	if id1 != SentinelIPv6ID || tc1 != 1 {
		t.Fatalf("source1: id=0x%08x tagCount=%d, want sentinel + 1 tag", id1, tc1)
	}
	tag, err := b.GetTag()
	if err != nil {
		t.Fatalf("tag decode: %v", err)
	}
	if tag.Name != "ipv6" {
		t.Fatalf("tag name = %q, want ipv6", tag.Name)
	}
	if got, ok := tag.Value.([]byte); !ok || !bytes.Equal(got, ip) {
		t.Fatalf("tag value mismatch: %x", tag.Value)
	}
	// source 2: real v4 id + 0 tags
	id2, _ := b.GetUInt32LE()
	_, _ = b.GetUInt16LE()
	tc2, _ := b.GetUInt8()
	if id2 != 0x04030201 || tc2 != 0 {
		t.Fatalf("source2: id=0x%08x tagCount=%d, want v4 id + 0 tags", id2, tc2)
	}
	t.Logf("tag-block: v6 source (sentinel id + ipv6 tag) + v4 source (0 tags) verified")
}

// TestGlobFoundSourcesSingleBlock pins the one-block-per-datagram framing: the
// sentinel UDP builder must produce exactly one OP_GLOBFOUNDSOURCES block, or a
// vanilla client's count*(4+2) coalescing skip would desync.
func TestGlobFoundSourcesSingleBlock(t *testing.T) {
	ip := v6(0x77)
	sources := []storage.Source{{ID: 12345, Port: 4662, IPv6: ip, IPv6Reachable: true}}
	buf, err := BuildGlobFoundSourcesSentinelPacket(testFileHash, sources)
	if err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	if raw[0] != PrED2K || raw[1] != OpGlobFoundSources {
		t.Fatalf("not a single OP_GLOBFOUNDSOURCES datagram: % x", raw[:2])
	}
	// Exactly: proto(1) op(1) hash(16) count(1) id(4) port(2) ipv6(16)
	if len(raw) != 1+1+16+1+4+2+16 {
		t.Fatalf("unexpected datagram length %d (extra block?)", len(raw))
	}
	t.Logf("single-block sentinel datagram length %d verified", len(raw))
}
