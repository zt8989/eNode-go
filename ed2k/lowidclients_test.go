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
