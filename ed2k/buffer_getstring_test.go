package ed2k

import "testing"

// TestGetStringRejectsTruncated pins L8: a declared string length longer than the
// bytes remaining now returns ErrOutOfBounds instead of a silently truncated
// string. Against the pre-fix build both truncation cases return a short string
// with a nil error (Get truncates to the remaining bytes).
func TestGetStringRejectsTruncated(t *testing.T) {
	// Length-prefixed form: uint16 prefix declares 10 bytes, only 3 follow.
	b := NewBufferFromBytes([]byte{0x0a, 0x00, 'a', 'b', 'c'})
	t.Logf("input: uint16 length prefix=10, payload bytes remaining=3")
	s, err := b.GetString()
	if err != ErrOutOfBounds {
		t.Fatalf("length-prefixed: got (%q, %v), want ErrOutOfBounds", s, err)
	}
	t.Logf("output: err=%v (rejected)", err)

	// Explicit-length form: ask for 8 bytes, only 4 present.
	b2 := NewBufferFromBytes([]byte{'w', 'x', 'y', 'z'})
	t.Logf("input: GetString(8) with 4 bytes present")
	s2, err2 := b2.GetString(8)
	if err2 != ErrOutOfBounds {
		t.Fatalf("explicit-length: got (%q, %v), want ErrOutOfBounds", s2, err2)
	}
	t.Logf("output: err=%v (rejected)", err2)

	// Sanity: an exact-fit read still succeeds and is not over-eager.
	b3 := NewBufferFromBytes([]byte{0x03, 0x00, 'a', 'b', 'c'})
	s3, err3 := b3.GetString()
	if err3 != nil || s3 != "abc" {
		t.Fatalf("exact fit: got (%q, %v), want (\"abc\", nil)", s3, err3)
	}
	t.Logf("output: exact-fit read = %q (accepted)", s3)
}
