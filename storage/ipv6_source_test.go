package storage

import (
	"bytes"
	"testing"
)

func TestMemoryEngineRoundTripsIPv6Source(t *testing.T) {
	m := NewMemoryEngine()
	hash := bytes.Repeat([]byte{0xab}, 16)
	ipv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}

	client := ClientInfo{
		ID:            0x0100007f,
		Port:          4662,
		Hash:          bytes.Repeat([]byte{0x11}, 16),
		IPv6:          ipv6,
		IPv6Reachable: true,
	}
	m.AddFile(File{Hash: hash, Name: "movie.avi", Size: 100}, client)

	got := m.GetSources(hash, 100)
	if len(got) != 1 {
		t.Fatalf("expected 1 source, got %d", len(got))
	}
	if !bytes.Equal(got[0].IPv6, ipv6) {
		t.Fatalf("ipv6 mismatch: got %x want %x", got[0].IPv6, ipv6)
	}
	if !got[0].IPv6Reachable {
		t.Fatal("expected IPv6Reachable to round-trip as true")
	}
	t.Logf("source: id=0x%08x ipv6=%x reachable=%v", got[0].ID, got[0].IPv6, got[0].IPv6Reachable)
}

func TestMemoryEngineRefreshesIPv6OnReAdd(t *testing.T) {
	m := NewMemoryEngine()
	hash := bytes.Repeat([]byte{0xcd}, 16)
	client := ClientInfo{ID: 0x0100007f, Port: 4662, Hash: bytes.Repeat([]byte{0x22}, 16)}
	m.AddFile(File{Hash: hash, Name: "a.bin", Size: 10}, client)

	// Same (id, port) re-offers with an IPv6 now known and reachable.
	client.IPv6 = []byte{0x26, 0x06, 0x47, 0, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11}
	client.IPv6Reachable = true
	m.AddFile(File{Hash: hash, Name: "a.bin", Size: 10}, client)

	got := m.GetSources(hash, 10)
	if len(got) != 1 {
		t.Fatalf("expected 1 source after re-add, got %d", len(got))
	}
	if !got[0].IPv6Reachable || len(got[0].IPv6) != 16 {
		t.Fatalf("re-add did not refresh IPv6: %+v", got[0])
	}
	t.Logf("refreshed source ipv6=%x reachable=%v", got[0].IPv6, got[0].IPv6Reachable)
}
