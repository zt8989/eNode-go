package ed2k

import (
	"strings"
	"testing"
)

// searchLeaf is a minimal well-formed text term: token 0x01, 2-byte length, "a".
var searchLeaf = []byte{0x01, 0x01, 0x00, 'a'}

// nestedAndExpr builds a well-formed tree nested `levels` deep along its left
// spine. A boolean node is `0x00 <op> <left> <right>` and takes *two* children,
// so each level needs its own right-hand leaf — a bare chain of 0x00 tokens
// would simply run out of bytes and fail on bounds rather than on depth.
func nestedAndExpr(levels int) []byte {
	out := make([]byte, 0, levels*6+len(searchLeaf))
	for i := 0; i < levels; i++ {
		out = append(out, 0x00, 0x00)
	}
	out = append(out, searchLeaf...)
	for i := 0; i < levels; i++ {
		out = append(out, searchLeaf...)
	}
	return out
}

// A 2-byte token that recurses twice with no depth counter lets a peer drive
// the parser past Go's 1 GB stack ceiling. That is a runtime throw rather than
// a panic, so it kills the process outright and no recover() could catch it.
// Reachable pre-login, and over UDP with no handshake at all.
func TestParseSearchExprRejectsDeepNesting(t *testing.T) {
	const levels = 100000
	payload := nestedAndExpr(levels)
	t.Logf("input: %d nested boolean levels in %d bytes", levels, len(payload))

	expr, err := ParseSearchExpr(NewBufferFromBytes(payload))
	t.Logf("output: expr=%v err=%v", expr != nil, err)

	if err == nil {
		t.Fatal("a 100000-level expression parsed successfully")
	}
	if !strings.Contains(err.Error(), "nested deeper") {
		t.Fatalf("expected a depth error, got %v", err)
	}
}

// The limit must not clip expressions eMule legitimately builds — it uses the
// same ceiling when generating them, so anything under it has to keep working.
func TestParseSearchExprDepthBoundary(t *testing.T) {
	cases := []struct {
		name      string
		levels    int
		wantError bool
	}{
		{"one below the limit", MaxSearchExprDepth - 1, false},
		{"at the limit", MaxSearchExprDepth, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := nestedAndExpr(tc.levels)
			expr, err := ParseSearchExpr(NewBufferFromBytes(payload))
			t.Logf("input: %d nested levels -> output: expr=%v err=%v", tc.levels, expr != nil, err)

			if tc.wantError {
				if err == nil {
					t.Fatalf("%d levels was accepted, want rejected", tc.levels)
				}
				return
			}
			if err != nil {
				t.Fatalf("%d levels was rejected: %v — this would break real clients", tc.levels, err)
			}
			if expr == nil {
				t.Fatal("no expression returned")
			}
		})
	}
}

// A flat, unnested query is the common case and must be unaffected.
func TestParseSearchExprSimpleQueryUnaffected(t *testing.T) {
	payload := []byte{0x01, 0x04, 0x00, 'f', 'o', 'o', 'd'}
	expr, err := ParseSearchExpr(NewBufferFromBytes(payload))
	if err != nil {
		t.Fatalf("a plain text search was rejected: %v", err)
	}
	t.Logf("input: plain text search -> output: kind=%d text=%q", expr.Kind, expr.Text)
	if expr.Text != "food" {
		t.Fatalf("got text %q, want %q", expr.Text, "food")
	}
}
