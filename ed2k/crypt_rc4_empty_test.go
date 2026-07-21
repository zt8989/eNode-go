package ed2k

import "testing"

// TestRC4CreateKeyEmptyKeyphrase pins L10: an empty keyphrase must not panic. The
// pre-fix loop indexes keyphrase[0] and computes `% len(keyphrase)`, so against a
// reverted build this test panics with "index out of range" / "integer divide by
// zero"; the deferred recover turns that into a test failure.
func TestRC4CreateKeyEmptyKeyphrase(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RC4CreateKey panicked on empty keyphrase: %v", r)
		}
	}()
	t.Logf("input: RC4CreateKey(keyphrase=[], drop=false)")
	k := RC4CreateKey([]byte{}, false)
	if k == nil {
		t.Fatalf("expected a non-nil key")
	}
	t.Logf("output: identity-permuted key returned, no panic (X=%d Y=%d State[0]=%d State[255]=%d)",
		k.X, k.Y, k.State[0], k.State[255])
}
