package ed2k

import (
	"testing"

	"enode/storage"
)

func makeSources(n int) []storage.Source {
	out := make([]storage.Source, n)
	for i := range out {
		out[i] = storage.Source{ID: uint32(i + 1), Port: uint16(4000 + i)}
	}
	return out
}

// The source count is one byte. With 256 sources, uint8(256) is 0: the client
// reads "no sources" and then treats the ~1536 bytes of source records that
// follow as the start of the next packet.
func TestFoundSourcesPacketCountMatchesRecords(t *testing.T) {
	cases := []struct {
		name  string
		count int
		want  int
	}{
		{"under the ceiling", 3, 3},
		{"at the ceiling", 255, 255},
		{"the wrapping case", 256, 255},
		{"well over", 1000, 255},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hash := make([]byte, 16)
			sources := makeSources(tc.count)
			t.Logf("input: %d sources", tc.count)

			packet, err := BuildFoundSourcesPacket(hash, sources)
			if err != nil {
				t.Fatal(err)
			}

			// Layout: protocol(1) size(4) opcode(1) hash(16) count(1) then records.
			// Payloads over 128 bytes are zlib-compressed on send, so inflate first.
			raw := packet.Bytes()
			if raw[0] == PrZlib {
				payload, err := InflateZlibPayload(raw[6:])
				if err != nil {
					t.Fatalf("inflate failed: %v", err)
				}
				raw = append(append([]byte{PrED2K}, raw[1:6]...), payload...)
			}
			const countOffset = 1 + 4 + 1 + 16
			got := int(raw[countOffset])
			records := (len(raw) - countOffset - 1) / 6 // uint32 id + uint16 port
			t.Logf("output: count byte=%d, records on the wire=%d (compressed=%t)",
				got, records, packet.Bytes()[0] == PrZlib)

			if got != tc.want {
				t.Fatalf("count byte mismatch: got %d want %d", got, tc.want)
			}
			if records != tc.want {
				t.Fatalf("record count mismatch: got %d want %d", records, tc.want)
			}
		})
	}
}

func TestGlobFoundSourcesPacketCountMatchesRecords(t *testing.T) {
	hash := make([]byte, 16)
	sources := makeSources(256)
	t.Logf("input: %d sources over UDP", len(sources))

	packet, err := BuildGlobFoundSourcesPacket(hash, sources)
	if err != nil {
		t.Fatal(err)
	}

	// UDP layout: protocol(1) opcode(1) hash(16) count(1) then records.
	raw := packet.Bytes()
	const countOffset = 1 + 1 + 16
	got := int(raw[countOffset])
	records := (len(raw) - countOffset - 1) / 6
	t.Logf("output: count byte=%d, records on the wire=%d", got, records)

	if got != storage.MaxWireSources {
		t.Fatalf("count byte mismatch: got %d want %d", got, storage.MaxWireSources)
	}
	if records != storage.MaxWireSources {
		t.Fatalf("record count mismatch: got %d want %d", records, storage.MaxWireSources)
	}
}

// The memory engine is the default, and it was the only one without a cap: MySQL
// and MongoDB get theirs from LIMIT 255.
func TestMemoryEngineCapsSourcesAtWireLimit(t *testing.T) {
	engine := storage.NewMemoryEngine()
	hash := make([]byte, 16)
	hash[0] = 0x42
	const offered = 300

	for i := 0; i < offered; i++ {
		engine.AddFile(
			storage.File{Hash: hash, Name: "big.iso", Size: 4096},
			storage.ClientInfo{ID: uint32(i + 1), Port: uint16(4000 + i), Hash: hash},
		)
	}
	t.Logf("input: %d distinct sources offered for one file", offered)

	bySize := engine.GetSources(hash, 4096)
	byHash := engine.GetSourcesByHash(hash)
	t.Logf("output: GetSources=%d GetSourcesByHash=%d", len(bySize), len(byHash))

	if len(bySize) != storage.MaxWireSources {
		t.Fatalf("GetSources returned %d, want %d", len(bySize), storage.MaxWireSources)
	}
	if len(byHash) != storage.MaxWireSources {
		t.Fatalf("GetSourcesByHash returned %d, want %d", len(byHash), storage.MaxWireSources)
	}
}
