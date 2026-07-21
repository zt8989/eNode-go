package ed2k

import "testing"

func TestListenNetworkSelection(t *testing.T) {
	cases := []struct {
		dualStack bool
		wantTCP   string
		wantUDP   string
	}{
		{false, "tcp4", "udp4"},
		{true, "tcp", "udp"},
	}
	for _, c := range cases {
		if got := tcpNetwork(c.dualStack); got != c.wantTCP {
			t.Errorf("tcpNetwork(%v) = %q, want %q", c.dualStack, got, c.wantTCP)
		}
		if got := udpNetwork(c.dualStack); got != c.wantUDP {
			t.Errorf("udpNetwork(%v) = %q, want %q", c.dualStack, got, c.wantUDP)
		}
		t.Logf("dualStack=%v -> tcp=%q udp=%q", c.dualStack, tcpNetwork(c.dualStack), udpNetwork(c.dualStack))
	}
}
