package storage

import "testing"

// A client's crypt options must survive from Connect through AddFile into the
// Source that GetSources returns, so BuildFoundSourcesObfuPacket can advertise
// them per source. Before the field was plumbed, GetSources reported
// CryptOptions=0 for every source regardless of what the client advertised.
func TestMemoryEngineCarriesCryptOptions(t *testing.T) {
	engine := NewMemoryEngine()
	owner := ClientInfo{
		Hash: []byte("0123456789abcdef"), ID: 0x0100007F, Port: 4662, CryptOptions: 0x03,
	}
	storeID, _ := engine.Connect(owner)
	owner.StoreID = storeID
	file := File{Hash: []byte("fedcba9876543210"), Size: 1024, Name: "foo.bin"}
	engine.AddFile(file, owner)

	sources := engine.GetSources(file.Hash, file.Size)
	t.Logf("input: client CryptOptions=0x03 offered file %q", file.Name)
	if len(sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(sources))
	}
	t.Logf("output: GetSources[0].CryptOptions=0x%02x", sources[0].CryptOptions)
	if sources[0].CryptOptions != 0x03 {
		t.Fatalf("Source.CryptOptions=0x%02x, want 0x03 — the field was not carried through AddFile", sources[0].CryptOptions)
	}
}
