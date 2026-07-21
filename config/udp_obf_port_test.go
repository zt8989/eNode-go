package config

import "testing"

// The obfuscated UDP port must default to tcp.port+12 — the port eMule hardwires
// for the server-UDP crypt-ping and the only source port it accepts the reply from
// on first contact (srchybrid/ServerList.cpp:294, GetServerByIPUDP :563-576).
func TestUDPObfuscatedPortDefaultsToTCPPlus12(t *testing.T) {
	cases := []struct {
		name string
		body string
		want uint16
	}{
		{
			name: "omitted → tcp default(5555)+12",
			body: "name: t\naddress: \"127.0.0.1\"\n",
			want: 5567,
		},
		{
			name: "omitted follows a custom tcp port",
			body: "name: t\naddress: \"127.0.0.1\"\ntcp:\n  port: 4661\n",
			want: 4673, // 4661 + 12
		},
		{
			name: "explicit value wins",
			body: "name: t\naddress: \"127.0.0.1\"\nudp:\n  portObfuscated: 9999\n",
			want: 9999,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(writeTempConfig(t, tc.body))
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("input: %q", tc.body)
			t.Logf("output: tcp.port=%d udp.portObfuscated=%d", cfg.TCP.Port, cfg.UDP.PortObfuscated)
			if cfg.UDP.PortObfuscated != tc.want {
				t.Fatalf("udp.portObfuscated=%d, want %d", cfg.UDP.PortObfuscated, tc.want)
			}
		})
	}
}
