package ed2k

import (
	"errors"
	"runtime"
	"testing"
)

// Both GetTags and GetFileList sized their slice straight from a 4-byte wire
// count, so six bytes on the wire reserved ~137 GB (tags) or ~275 GB (file
// records). Assert on the error and on allocation rather than on a crash: a
// zero-length slice with a huge capacity may only reserve address space on some
// platforms, and an out-of-memory throw is unrecoverable so it cannot be caught.
func TestGetTagsRejectsImplausibleCount(t *testing.T) {
	// count = 0xFFFFFFFF followed by one valid 2-byte short-format tag.
	payload := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x90, 0x01}
	t.Logf("input: % x (count=%d, %d bytes remain after it)", payload, 0xFFFFFFFF, 2)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	tags, err := NewBufferFromBytes(payload).GetTags()

	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("output: tags=%d err=%v allocated=%d bytes", len(tags), err, allocated)

	if err == nil {
		t.Fatalf("a count of 0xFFFFFFFF was accepted, returning %d tags", len(tags))
	}
	if !errors.Is(err, ErrOutOfBounds) {
		t.Fatalf("expected ErrOutOfBounds, got %v", err)
	}
	if allocated > 1<<20 {
		t.Fatalf("allocated %d bytes for a 6-byte packet", allocated)
	}
}

func TestGetFileListRejectsImplausibleCount(t *testing.T) {
	payload := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00}
	t.Logf("input: % x (count=%d)", payload, 0xFFFFFFFF)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	files, err := NewBufferFromBytes(payload).GetFileList()

	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("output: files=%d err=%v allocated=%d bytes", len(files), err, allocated)

	if err == nil {
		t.Fatalf("a count of 0xFFFFFFFF was accepted, returning %d records", len(files))
	}
	if !errors.Is(err, ErrOutOfBounds) {
		t.Fatalf("expected ErrOutOfBounds, got %v", err)
	}
	if allocated > 1<<20 {
		t.Fatalf("allocated %d bytes for a 6-byte packet", allocated)
	}
}

// The bound is derived from the smallest legal encoding, so a packet that is
// exactly full of minimum-size tags must still parse. This is what stops the
// check from being tightened into something that rejects real traffic.
func TestGetTagsAcceptsDenselyPackedTags(t *testing.T) {
	const count = 4
	payload := []byte{count, 0x00, 0x00, 0x00}
	for i := 0; i < count; i++ {
		payload = append(payload, 0x90, 0x01) // short format, zero-length string
	}
	t.Logf("input: %d bytes declaring %d tags of %d bytes each", len(payload), count, minTagBytes)

	tags, err := NewBufferFromBytes(payload).GetTags()
	t.Logf("output: tags=%d err=%v", len(tags), err)

	if err != nil {
		t.Fatalf("a densely packed but legal tag list was rejected: %v", err)
	}
	if len(tags) != count {
		t.Fatalf("got %d tags, want %d", len(tags), count)
	}
}

// A count one past what the remaining bytes can supply must be rejected, and
// the error must be the framing error — not a silently truncated short list.
func TestGetTagsCountBoundary(t *testing.T) {
	// 4 bytes of payload can hold at most 2 minimum-size tags.
	payload := []byte{0x03, 0x00, 0x00, 0x00, 0x90, 0x01, 0x90, 0x01}
	t.Logf("input: declares 3 tags but only %d bytes follow (max %d tags)",
		len(payload)-4, (len(payload)-4)/minTagBytes)

	tags, err := NewBufferFromBytes(payload).GetTags()
	t.Logf("output: tags=%d err=%v", len(tags), err)

	if err == nil {
		t.Fatalf("an over-declared count was accepted, returning %d tags", len(tags))
	}
	if len(tags) != 0 {
		t.Fatalf("returned %d tags alongside the error — callers would frame from the wrong offset", len(tags))
	}
}
