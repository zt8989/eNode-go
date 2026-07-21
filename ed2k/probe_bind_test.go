package ed2k

import "testing"

func TestLocalBindForNetwork(t *testing.T) {
	cases := []struct {
		network string
		address string
		wantNil bool
		wantIP  string
	}{
		{"tcp4", "192.0.2.9", false, "192.0.2.9"},
		{"tcp6", "2001:db8::9", false, "2001:db8::9"},
		{"tcp4", "2001:db8::9", true, ""}, // family mismatch
		{"tcp6", "192.0.2.9", true, ""},   // family mismatch
		{"tcp4", "0.0.0.0", true, ""},     // wildcard
		{"tcp6", "::", true, ""},          // wildcard
		{"tcp4", "", true, ""},            // empty
		{"tcp4", "not-an-ip", true, ""},   // unparsable
	}
	for _, c := range cases {
		got := localBindForNetwork(c.network, c.address)
		if c.wantNil {
			if got != nil {
				t.Errorf("localBindForNetwork(%q, %q) = %v, want nil", c.network, c.address, got)
			}
			continue
		}
		if got == nil || got.String() != c.wantIP {
			t.Errorf("localBindForNetwork(%q, %q) = %v, want %s", c.network, c.address, got, c.wantIP)
		}
	}
	t.Logf("family-aware local bind selection verified for %d cases", len(cases))
}
