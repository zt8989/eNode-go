package ed2k

import (
	"bytes"
	"compress/zlib"
	"errors"
	"runtime"
	"testing"
)

// compressZeros returns a zlib stream that inflates to n bytes of zeros. Zeros
// hit close to zlib's best ratio, which is the point: the compressed form stays
// well inside the wire-size ceiling that Packet.Init enforces.
func compressZeros(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 1<<20)
	for written := 0; written < n; {
		size := len(chunk)
		if remaining := n - written; remaining < size {
			size = remaining
		}
		if _, err := zw.Write(chunk[:size]); err != nil {
			t.Fatal(err)
		}
		written += size
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// MaxTCPPacketSize bounds only the size a peer *declares* on the wire. zlib
// reaches roughly 1032:1, so a packet small enough to pass that check still
// inflates to gigabytes. Before the cap, this allocated the full inflated size.
func TestInflateZlibPayloadRejectsBomb(t *testing.T) {
	const inflatedSize = 200 << 20 // 200 MiB
	payload := compressZeros(t, inflatedSize)

	t.Logf("input: compressed=%d bytes, inflates to %d bytes (ratio %.0f:1)",
		len(payload), inflatedSize, float64(inflatedSize)/float64(len(payload)))

	// The premise of the attack: this payload is a legal packet by wire size.
	if len(payload) > MaxTCPPacketSize {
		t.Fatalf("test payload is %d bytes, above the %d wire cap — Init would "+
			"reject it before inflation and the test would prove nothing",
			len(payload), MaxTCPPacketSize)
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	out, err := InflateZlibPayload(payload)

	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc

	t.Logf("output: err=%v outputLen=%d allocated=%d bytes", err, len(out), allocated)

	if !errors.Is(err, ErrInflatedTooLarge) {
		t.Fatalf("expected ErrInflatedTooLarge, got err=%v with %d bytes", err, len(out))
	}
	// Bounded, not zero: the reader still buffers up to the ceiling before it
	// can tell the stream is oversized, and bytes.Buffer growth plus -race
	// overhead land it a little above that. The unfixed code allocated ~1.2 GB
	// here, so this has two orders of magnitude of headroom and stays
	// discriminating without being flaky.
	if limit := uint64(16 * MaxTCPPacketSize); allocated > limit {
		t.Fatalf("allocated %d bytes, want under %d", allocated, limit)
	}
}

// The cap must not break the compression the protocol actually uses — eMule
// zlib-compresses ordinary search results and source lists.
func TestInflateZlibPayloadAcceptsNormalPayload(t *testing.T) {
	original := bytes.Repeat([]byte("eNode payload "), 1000)
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(original); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	t.Logf("input: compressed=%d bytes -> expect %d bytes out", buf.Len(), len(original))

	out, err := InflateZlibPayload(buf.Bytes())
	if err != nil {
		t.Fatalf("a normal payload was rejected: %v", err)
	}
	t.Logf("output: inflated=%d bytes err=<nil>", len(out))

	if !bytes.Equal(out, original) {
		t.Fatal("inflated payload does not match the original")
	}
}

// A stream that inflates to exactly the ceiling is legal; one byte more is not.
// This pins the off-by-one, which is the whole reason the reader takes
// MaxTCPPacketSize+1 rather than MaxTCPPacketSize.
func TestInflateZlibPayloadBoundary(t *testing.T) {
	cases := []struct {
		name      string
		size      int
		wantError bool
	}{
		{"exactly at the ceiling", MaxTCPPacketSize, false},
		{"one byte over", MaxTCPPacketSize + 1, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := InflateZlibPayload(compressZeros(t, tc.size))
			t.Logf("input: inflates to %d bytes -> output: err=%v len=%d", tc.size, err, len(out))

			if tc.wantError {
				if !errors.Is(err, ErrInflatedTooLarge) {
					t.Fatalf("expected ErrInflatedTooLarge, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("a payload at the ceiling was rejected: %v", err)
			}
			if len(out) != tc.size {
				t.Fatalf("got %d bytes, want %d", len(out), tc.size)
			}
		})
	}
}
