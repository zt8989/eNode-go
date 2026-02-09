package ed2k

import (
	"enode/storage"
	"testing"
)

func TestBuildGlobPackets(t *testing.T) {
	hash := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	p, err := BuildGlobFoundSourcesPacket(hash, []storage.Source{{ID: 1, Port: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Bytes()[0] != PrED2K || p.Bytes()[1] != OpGlobFoundSources {
		t.Fatalf("bad packet header")
	}

	packets, err := BuildGlobSearchResPackets([]storage.File{{
		Hash: hash, Name: "x", Size: 1, Type: "Pro", Sources: 1, Completed: 1, SourceID: 1, SourcePort: 2,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 1 || packets[0].Bytes()[1] != OpGlobSearchRes {
		t.Fatalf("bad glob search res packet")
	}
}

func TestBuildGlobServStatAndDesc(t *testing.T) {
	cfg := UDPConfig{
		Name: "n", Description: "d", DynIP: "dyn", UDPFlags: 1, UDPPortObf: 2, TCPPortObf: 3, UDPServerKey: 4, MaxConnections: 5,
	}
	p, err := BuildGlobServStatResPacket(7, cfg, 10, 20, 30)
	if err != nil {
		t.Fatal(err)
	}
	if p.Bytes()[1] != OpGlobServStatRes {
		t.Fatalf("bad opcode")
	}
	d, err := BuildServerDescResPacket(7, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if d.Bytes()[1] != OpServerDescRes {
		t.Fatalf("bad opcode")
	}
}
