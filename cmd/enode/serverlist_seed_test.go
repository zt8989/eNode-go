package main

import (
	"testing"

	"enode/config"
	"enode/storage"
)

// TestServerListSeededFromConfig pins L1: seedServers loads the configured peer
// servers into storage (the only caller of AddServer outside tests), and skips an
// entry with an unparseable IP rather than aborting the whole list. Against a build
// with the seeding removed, ServersAll() is empty.
func TestServerListSeededFromConfig(t *testing.T) {
	engine := storage.NewMemoryEngine()
	entries := []config.ServerEntry{
		{IP: "111.222.111.222", Port: 1234},
		{IP: "123.123.234.234", Port: 2345},
		{IP: "not-an-ip", Port: 9999}, // invalid → skipped, must not drop the rest
	}
	t.Logf("input: %d entries (one with an invalid IP)", len(entries))
	seedServers(engine, entries)

	got := engine.ServersAll()
	t.Logf("output: %d server(s) seeded: %+v", len(got), got)
	if len(got) != 2 {
		t.Fatalf("want 2 valid servers seeded, got %d", len(got))
	}
	if got[0].IP != "111.222.111.222" || got[0].Port != 1234 {
		t.Fatalf("entry 0 mismatch: %+v", got[0])
	}
	if got[1].IP != "123.123.234.234" || got[1].Port != 2345 {
		t.Fatalf("entry 1 mismatch: %+v", got[1])
	}
}

// TestServerListEmptyByDefault confirms an omitted `servers:` seeds nothing — the
// unchanged default, and correct where the Node original shipped invalid dummies.
func TestServerListEmptyByDefault(t *testing.T) {
	engine := storage.NewMemoryEngine()
	seedServers(engine, nil)
	if n := engine.ServersCount(); n != 0 {
		t.Fatalf("want empty server list by default, got %d", n)
	}
	t.Logf("output: no servers seeded for empty config")
}
