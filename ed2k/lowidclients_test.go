package ed2k

import "testing"

func TestLowIDClientsLifecycle(t *testing.T) {
	l := NewLowIDClients(true)
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
	l := NewLowIDClients(false)
	if _, ok := l.Add("x"); ok {
		t.Fatalf("expected add to fail")
	}
}

func TestLowIDClientsAddByEndpointDeterministicAndRange(t *testing.T) {
	l := NewLowIDClients(true)
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
	l := NewLowIDClients(true)
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
