package ed2k

import (
	"net"
	"testing"
)

func TestNormalizeIPCollapsesMappedV4(t *testing.T) {
	mapped := net.ParseIP("::ffff:1.2.3.4")
	got := NormalizeIP(mapped)
	if got.To4() == nil {
		t.Fatalf("mapped v4 should collapse to 4-byte form, got %v (%d bytes)", got, len(got))
	}
	if got.String() != "1.2.3.4" {
		t.Fatalf("normalized address mismatch: %s", got.String())
	}
	t.Logf("input: %v -> %v (%d bytes)", mapped, got, len(got))
}

func TestIPv4ToUint32LEMatchesStringParser(t *testing.T) {
	want, err := IPv4ToInt32LE("1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := IPv4ToUint32LE(net.ParseIP("1.2.3.4"))
	if !ok {
		t.Fatal("expected an IPv4 result")
	}
	if got != want {
		t.Fatalf("byte order mismatch with IPv4ToInt32LE: got 0x%08x want 0x%08x", got, want)
	}
	// A v6 address has no HighID.
	if _, ok := IPv4ToUint32LE(net.ParseIP("2001:db8::1")); ok {
		t.Fatal("v6 address must not yield a uint32")
	}
	t.Logf("1.2.3.4 -> 0x%08x (matches string parser)", got)
}

func TestIPv6BytesRejectsV4(t *testing.T) {
	if _, ok := IPv6Bytes(net.ParseIP("1.2.3.4")); ok {
		t.Fatal("IPv4 must not yield 16-byte v6 form")
	}
	if _, ok := IPv6Bytes(net.ParseIP("::ffff:1.2.3.4")); ok {
		t.Fatal("mapped v4 must not yield 16-byte v6 form")
	}
	b, ok := IPv6Bytes(net.ParseIP("2001:db8::1"))
	if !ok {
		t.Fatal("expected a v6 result")
	}
	want := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	if b != want {
		t.Fatalf("bytes mismatch: got %x want %x", b, want)
	}
	t.Logf("2001:db8::1 -> %x (network order)", b)
}

func TestIsPublicIPv6(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"2001:db8::1", true},
		{"2606:4700:4700::1111", true},
		{"::1", false},            // loopback
		{"fe80::1", false},        // link-local
		{"fc00::1", false},        // unique-local
		{"ff02::1", false},        // multicast
		{"::", false},             // unspecified
		{"1.2.3.4", false},        // IPv4
		{"::ffff:1.2.3.4", false}, // mapped IPv4
	}
	for _, c := range cases {
		if got := IsPublicIPv6(net.ParseIP(c.in)); got != c.want {
			t.Errorf("IsPublicIPv6(%s) = %v, want %v", c.in, got, c.want)
		}
		t.Logf("IsPublicIPv6(%s) = %v", c.in, IsPublicIPv6(net.ParseIP(c.in)))
	}
}
