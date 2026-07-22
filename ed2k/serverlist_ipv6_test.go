package ed2k

import (
	"bytes"
	"net"
	"testing"

	"enode/storage"
)

// framing: <protocol:1><size:4 LE><opcode:1><payload>. Opcode is byte 5, the
// v4count is byte 6.
const serverListHeaderLen = 6 // protocol + size + opcode

func TestClassifyServerIP(t *testing.T) {
	cases := []struct {
		ip      string
		wantFam int
	}{
		{"10.0.0.1", 4},
		{"255.255.255.255", 4},
		{"2001:db8::1", 6},
		{"fe80::1", 0}, // link-local
		{"::1", 0},     // loopback
		{"fc00::1", 0}, // unique-local / private
		{"not-an-ip", 0},
		{"", 0},
	}
	for _, tc := range cases {
		_, _, fam := ClassifyServerIP(tc.ip)
		t.Logf("input=%q output fam=%d (want %d)", tc.ip, fam, tc.wantFam)
		if fam != tc.wantFam {
			t.Fatalf("ClassifyServerIP(%q) fam = %d, want %d", tc.ip, fam, tc.wantFam)
		}
	}
}

// TestBuildServerListPacketV6Wire pins the widened wire: the classic v4 block,
// then a trailing v6 block of <ipv6:16 network order><port:uint16 LE> entries.
func TestBuildServerListPacketV6Wire(t *testing.T) {
	servers := []storage.Server{
		{IP: "10.3.2.1", Port: 4661},
		{IP: "2001:db8::1", Port: 5000},
		{IP: "192.0.2.9", Port: 4662},
		{IP: "2001:db8::2", Port: 5001},
	}
	t.Logf("input: %d servers (2 v4, 2 v6), includeV6=true", len(servers))

	pkt, err := BuildServerListPacket(servers, true)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	b := pkt.Bytes()
	t.Logf("output: % x", b)

	if b[0] != PrED2K {
		t.Fatalf("protocol = 0x%02x, want 0x%02x", b[0], PrED2K)
	}
	if b[5] != OpServerList {
		t.Fatalf("opcode = 0x%02x, want 0x%02x", b[5], OpServerList)
	}

	// v4 block. An IPv4 a.b.c.d packs LE, so it lands on the wire as bytes a,b,c,d.
	if b[6] != 2 {
		t.Fatalf("v4count = %d, want 2", b[6])
	}
	off := 7
	wantV4a := []byte{10, 3, 2, 1, 0x35, 0x12} // 4661 = 0x1235 -> LE 35 12
	if got := b[off : off+6]; !bytes.Equal(got, wantV4a) {
		t.Fatalf("v4 entry 0 = % x, want % x", got, wantV4a)
	}
	off += 6
	wantV4b := []byte{192, 0, 2, 9, 0x36, 0x12} // 4662 = 0x1236 -> LE 36 12
	if got := b[off : off+6]; !bytes.Equal(got, wantV4b) {
		t.Fatalf("v4 entry 1 = % x, want % x", got, wantV4b)
	}
	off += 6

	// v6 block.
	if b[off] != 2 {
		t.Fatalf("v6count = %d, want 2", b[off])
	}
	off++
	v6a := net.ParseIP("2001:db8::1").To16()
	if got := b[off : off+16]; !bytes.Equal(got, v6a) {
		t.Fatalf("v6 entry 0 ip = % x, want % x", got, v6a)
	}
	off += 16
	if b[off] != 0x88 || b[off+1] != 0x13 { // 5000 = 0x1388 -> LE 88 13
		t.Fatalf("v6 entry 0 port = %02x %02x, want 88 13", b[off], b[off+1])
	}
	off += 2
	v6b := net.ParseIP("2001:db8::2").To16()
	if got := b[off : off+16]; !bytes.Equal(got, v6b) {
		t.Fatalf("v6 entry 1 ip = % x, want % x", got, v6b)
	}
	off += 16
	if b[off] != 0x89 || b[off+1] != 0x13 { // 5001 = 0x1389 -> LE 89 13
		t.Fatalf("v6 entry 1 port = %02x %02x, want 89 13", b[off], b[off+1])
	}
	off += 2

	if off != len(b) {
		t.Fatalf("parsed %d of %d bytes; unexpected trailing data", off, len(b))
	}
}

// TestBuildServerListPacketByteIdenticalWhenNoV6 pins that includeV6=false and
// includeV6=true-with-no-v6-servers both produce the exact classic packet — no
// trailing block, not even a zero v6count byte.
func TestBuildServerListPacketByteIdenticalWhenNoV6(t *testing.T) {
	v4only := []storage.Server{
		{IP: "10.0.0.1", Port: 4661},
		{IP: "10.0.0.2", Port: 4662},
	}
	p1, err := BuildServerListPacket(v4only, false)
	if err != nil {
		t.Fatalf("build includeV6=false: %v", err)
	}
	p2, err := BuildServerListPacket(v4only, true)
	if err != nil {
		t.Fatalf("build includeV6=true: %v", err)
	}
	a := p1.Bytes()
	b := p2.Bytes()
	t.Logf("input: 2 v4 servers, no v6")
	t.Logf("output: includeV6=false % x", a)
	t.Logf("output: includeV6=true  % x", b)

	if !bytes.Equal(a, b) {
		t.Fatalf("packets differ with no v6 servers: v6-off=% x v6-on=% x", a, b)
	}
	wantLen := serverListHeaderLen + 1 + 2*6 // header + v4count + two v4 entries
	if len(a) != wantLen {
		t.Fatalf("length = %d, want %d (no trailing v6 block)", len(a), wantLen)
	}
}

// TestBuildServerListPacketV6SuppressedWhenDisabled pins that a v6 entry is dropped
// entirely when includeV6 is false, leaving a pure classic packet.
func TestBuildServerListPacketV6SuppressedWhenDisabled(t *testing.T) {
	servers := []storage.Server{
		{IP: "10.0.0.1", Port: 4661},
		{IP: "2001:db8::1", Port: 5000},
	}
	pkt, err := BuildServerListPacket(servers, false)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	b := pkt.Bytes()
	t.Logf("input: 1 v4 + 1 v6 server, includeV6=false")
	t.Logf("output: % x", b)

	if b[6] != 1 {
		t.Fatalf("v4count = %d, want 1", b[6])
	}
	wantLen := serverListHeaderLen + 1 + 6 // header + v4count + one v4 entry
	if len(b) != wantLen {
		t.Fatalf("length = %d, want %d (v6 entry must be suppressed)", len(b), wantLen)
	}
}

// TestBuildServerListPacketSkipsInvalid pins that an unclassifiable entry (garbage,
// or a non-public v6 like link-local) is skipped without failing the packet or
// shifting the counts — the old builder errored the whole list on the first bad IP.
func TestBuildServerListPacketSkipsInvalid(t *testing.T) {
	servers := []storage.Server{
		{IP: "10.0.0.1", Port: 4661},    // v4 kept
		{IP: "not-an-ip", Port: 4662},   // garbage skipped
		{IP: "fe80::1", Port: 4663},     // link-local v6 skipped
		{IP: "2001:db8::1", Port: 5000}, // public v6 kept
	}
	pkt, err := BuildServerListPacket(servers, true)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	b := pkt.Bytes()
	t.Logf("input: 1 valid v4, 1 garbage, 1 link-local v6, 1 public v6")
	t.Logf("output: % x", b)

	if b[6] != 1 {
		t.Fatalf("v4count = %d, want 1 (garbage skipped)", b[6])
	}
	v6countOff := 7 + 6 // after v4count + one v4 entry
	if b[v6countOff] != 1 {
		t.Fatalf("v6count = %d, want 1 (link-local skipped)", b[v6countOff])
	}
}
