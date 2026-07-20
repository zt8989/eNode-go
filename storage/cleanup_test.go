package storage

import (
	"sync/atomic"
	"testing"
	"time"
)

// A file whose last source has gone must survive by default, and must still be
// findable. Kad and source exchange can locate peers the server no longer knows
// about, so the search entry remains the thing that lets a user discover the
// hash at all.
func TestMemoryCleanupKeepsZeroSourceFilesByDefault(t *testing.T) {
	engine := NewMemoryEngine()
	owner := ClientInfo{Hash: []byte("0123456789abcdef"), ID: 0x0100007F, Port: 4662}
	storeID, _ := engine.Connect(owner)
	owner.StoreID = storeID
	engine.AddFile(File{Hash: []byte("fedcba9876543210"), Size: 1024, Name: "foo.bin"}, owner)
	engine.Disconnect(owner)

	result, err := engine.CleanupStale(time.Hour, CleanupOptions{KeepZeroSourceFiles: true})
	if err != nil {
		t.Fatal(err)
	}
	found := engine.FindBySearch(&SearchExpr{Kind: SearchText, Text: "foo"})

	t.Logf("input: one file whose only source disconnected, keepZeroSourceFiles=true")
	t.Logf("output: removed files=%d, search returns %d file(s)", result.Files, len(found))

	if result.Files != 0 {
		t.Fatalf("removed %d files despite keepZeroSourceFiles", result.Files)
	}
	if len(found) != 1 {
		t.Fatalf("search returned %d files, want 1 — the entry is how the hash stays discoverable", len(found))
	}
	// And its source count must be truthful, not the value the client reported.
	if found[0].Sources != 0 {
		t.Fatalf("Sources=%d, want 0", found[0].Sources)
	}
}

// With the option off the file goes. This is the opt-in behaviour, so it has to
// actually work when selected.
func TestMemoryCleanupRemovesZeroSourceFilesWhenConfigured(t *testing.T) {
	engine := NewMemoryEngine()
	owner := ClientInfo{Hash: []byte("0123456789abcdef"), ID: 0x0100007F, Port: 4662}
	storeID, _ := engine.Connect(owner)
	owner.StoreID = storeID
	engine.AddFile(File{Hash: []byte("fedcba9876543210"), Size: 1024, Name: "foo.bin"}, owner)
	engine.Disconnect(owner)

	result, err := engine.CleanupStale(time.Hour, CleanupOptions{KeepZeroSourceFiles: false})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: keepZeroSourceFiles=false")
	t.Logf("output: removed files=%d, FilesCount=%d", result.Files, engine.FilesCount())

	if result.Files != 1 {
		t.Fatalf("removed %d files, want 1", result.Files)
	}
	if engine.FilesCount() != 0 {
		t.Fatalf("FilesCount=%d after cleanup, want 0", engine.FilesCount())
	}
}

// The counter recompute is the constraint that makes cleanup safe: File.Sources
// feeds the `sources > N` search filter and the count advertised in
// OP_SEARCHRESULT, so a stale value overstates reality permanently.
func TestMemoryCleanupRecomputesSourceCount(t *testing.T) {
	engine := NewMemoryEngine()
	file := File{Hash: []byte("fedcba9876543210"), Size: 1024, Name: "foo.bin"}

	var owners []ClientInfo
	for i := 0; i < 3; i++ {
		owner := ClientInfo{
			Hash: []byte{byte(i), '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'},
			ID:   uint32(0x0100007F + i),
			Port: uint16(4662 + i),
		}
		storeID, _ := engine.Connect(owner)
		owner.StoreID = storeID
		engine.AddFile(file, owner)
		owners = append(owners, owner)
	}

	engine.Disconnect(owners[0])
	engine.Disconnect(owners[1])

	if _, err := engine.CleanupStale(time.Hour, CleanupOptions{KeepZeroSourceFiles: true}); err != nil {
		t.Fatal(err)
	}

	found := engine.FindBySearch(&SearchExpr{Kind: SearchText, Text: "foo"})
	actual := len(engine.GetSourcesByHash(file.Hash))
	t.Logf("input: 3 sources, 2 disconnected")
	t.Logf("output: File.Sources=%d, actual live sources=%d", found[0].Sources, actual)

	if int(found[0].Sources) != actual {
		t.Fatalf("File.Sources=%d but %d sources remain — the counter drifted", found[0].Sources, actual)
	}
	if actual != 1 {
		t.Fatalf("%d sources remain, want 1", actual)
	}
}

// A zero or negative maxAge would delete everything. Reject it rather than
// interpreting it as "expire immediately".
func TestCleanupStaleRejectsNonPositiveMaxAge(t *testing.T) {
	engine := NewMemoryEngine()
	for _, maxAge := range []time.Duration{0, -time.Hour} {
		_, err := engine.CleanupStale(maxAge, CleanupOptions{})
		t.Logf("input: maxAge=%s -> output: err=%v", maxAge, err)
		if err == nil {
			t.Fatalf("maxAge=%s was accepted", maxAge)
		}
	}
}

// cleanupSpy records sweeps without touching a database.
type cleanupSpy struct {
	Engine
	sweeps atomic.Int64
	maxAge atomic.Int64
}

func (s *cleanupSpy) CleanupStale(maxAge time.Duration, opts CleanupOptions) (CleanupResult, error) {
	s.sweeps.Add(1)
	s.maxAge.Store(int64(maxAge))
	return CleanupResult{Clients: 1, Sources: 2}, nil
}

func TestStartCleanupRunsOnIntervalAndStops(t *testing.T) {
	spy := &cleanupSpy{Engine: NewMemoryEngine()}
	stop := StartCleanup(spy, 20*time.Millisecond, time.Hour, CleanupOptions{KeepZeroSourceFiles: true})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && spy.sweeps.Load() < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	ran := spy.sweeps.Load()
	t.Logf("input: 20ms interval -> output: %d sweeps, maxAge passed through=%s",
		ran, time.Duration(spy.maxAge.Load()))

	if ran < 2 {
		t.Fatalf("only %d sweeps ran", ran)
	}
	if time.Duration(spy.maxAge.Load()) != time.Hour {
		t.Fatalf("maxAge=%s, want 1h", time.Duration(spy.maxAge.Load()))
	}

	stop()
	after := spy.sweeps.Load()
	time.Sleep(80 * time.Millisecond)
	t.Logf("output: sweeps after stop: %d -> %d", after, spy.sweeps.Load())

	if spy.sweeps.Load() > after+1 {
		t.Fatalf("cleanup kept running after stop: %d -> %d", after, spy.sweeps.Load())
	}
}

// The first sweep must wait one interval. Running at startup would turn a crash
// loop into repeated full-table maintenance.
func TestStartCleanupDoesNotSweepImmediately(t *testing.T) {
	spy := &cleanupSpy{Engine: NewMemoryEngine()}
	stop := StartCleanup(spy, time.Hour, time.Hour, CleanupOptions{})
	defer stop()

	time.Sleep(50 * time.Millisecond)
	t.Logf("output: sweeps 50ms after start with a 1h interval: %d", spy.sweeps.Load())

	if spy.sweeps.Load() != 0 {
		t.Fatalf("%d sweeps ran before the first interval elapsed", spy.sweeps.Load())
	}
}
