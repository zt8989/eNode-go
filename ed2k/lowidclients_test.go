package ed2k

import "testing"

func TestLowIDClientsLifecycle(t *testing.T) {
	l := NewLowIDClients(true, 0, 0)
	id, ok := l.Add("c1")
	if !ok || id == 0 {
		t.Fatalf("add failed")
	}
	if l.Count() != 1 {
		t.Fatalf("count mismatch")
	}
	v, ok := l.Get(id)
	if !ok || v.(string) != "c1" {
		t.Fatalf("get mismatch")
	}
	l.Remove(id)
	if l.Count() != 0 {
		t.Fatalf("count mismatch after remove")
	}
}

func TestLowIDClientsDisallowed(t *testing.T) {
	l := NewLowIDClients(false, 0, 0)
	if _, ok := l.Add("x"); ok {
		t.Fatalf("expected add to fail")
	}
}

// TestNewLowIDClientsHonorsConfiguredRange pins L4: tcp.minLowID / tcp.maxLowID
// now bound the allocator. Against the pre-fix build (hardcoded 1..0xffffff) the
// allocated IDs fall outside [100,200] and the pool never reports exhausted at 101.
func TestNewLowIDClientsHonorsConfiguredRange(t *testing.T) {
	const min, max = uint32(100), uint32(200)
	l := NewLowIDClients(true, min, max)
	t.Logf("input: NewLowIDClients(allow=true, min=%d, max=%d) rangeSize=%d", min, max, max-min+1)

	seen := map[uint32]bool{}
	for i := 0; i < int(max-min+1); i++ {
		id, ok := l.AddByEndpoint(uint32(0x0a000000+i), uint16(1000+i), i)
		if !ok {
			t.Fatalf("allocation %d failed while pool should have room", i)
		}
		if id < min || id > max {
			t.Fatalf("allocated id %d outside configured range [%d,%d]", id, min, max)
		}
		if seen[id] {
			t.Fatalf("allocated duplicate id %d", id)
		}
		seen[id] = true
	}
	t.Logf("output: %d unique IDs allocated, all within [%d,%d]", len(seen), min, max)

	if _, ok := l.AddByEndpoint(0xdeadbeef, 9999, "overflow"); ok {
		t.Fatalf("expected exhaustion after %d allocations, but another succeeded", max-min+1)
	}
	t.Logf("output: pool correctly reported exhausted after %d allocations", max-min+1)
}

// TestNewLowIDClientsDefaultsOnZero pins that an omitted config (0/0) resolves to
// the full 1..0xffffff range rather than a degenerate one-element pool.
func TestNewLowIDClientsDefaultsOnZero(t *testing.T) {
	l := NewLowIDClients(true, 0, 0)
	t.Logf("input: NewLowIDClients(allow=true, min=0, max=0)")
	if l.min != 1 || l.max != 0xffffff {
		t.Fatalf("expected default range 1..0xffffff, got %d..%d", l.min, l.max)
	}
	t.Logf("output: resolved range %d..0x%x", l.min, l.max)
}

func TestLowIDClientsAddByEndpointDeterministicAndRange(t *testing.T) {
	l := NewLowIDClients(true, 0, 0)
	ip, err := IPv4ToInt32LE("66.154.127.95")
	if err != nil {
		t.Fatalf("parse ip: %v", err)
	}
	id1, ok := l.AddByEndpoint(ip, 5565, "c1")
	if !ok {
		t.Fatalf("first add failed")
	}
	if id1 == 0 || id1 > 0x00ffffff {
		t.Fatalf("id out of lowid range: %d", id1)
	}
	l.Remove(id1)
	id2, ok := l.AddByEndpoint(ip, 5565, "c2")
	if !ok {
		t.Fatalf("second add failed")
	}
	if id1 != id2 {
		t.Fatalf("determinism mismatch: id1=%d id2=%d", id1, id2)
	}
}

func TestLowIDClientsAddByEndpointRehashOnCollision(t *testing.T) {
	l := NewLowIDClients(true, 0, 0)
	l.min = 1
	l.max = 2
	id1, ok := l.AddByEndpoint(0x01020304, 1111, "a")
	if !ok {
		t.Fatalf("first add failed")
	}
	id2, ok := l.AddByEndpoint(0x01020304, 1111, "b")
	if !ok {
		t.Fatalf("second add failed")
	}
	if id1 == id2 {
		t.Fatalf("expected rehash to find different lowid, got same id=%d", id1)
	}
	if id1 < 1 || id1 > 2 || id2 < 1 || id2 > 2 {
		t.Fatalf("ids out of expected narrowed range: %d %d", id1, id2)
	}
	if l.Count() != 2 {
		t.Fatalf("count mismatch: %d", l.Count())
	}
	if _, ok := l.AddByEndpoint(0x01020304, 1111, "c"); ok {
		t.Fatalf("expected add to fail when pool exhausted")
	}
}
