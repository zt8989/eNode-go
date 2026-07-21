package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSetDefaultsPortsMatchOriginal pins L3: a YAML that omits the port keys must
// fall back to the shipped ports — TCP 5555/5565, plaintext UDP 5559 — not the
// classic eDonkey 4661/4662/4665/4666. The obfuscated UDP port is the exception:
// it defaults to tcp.port+12 (5567), the port eMule pings for the crypt-ping (see
// TestUDPObfuscatedPortDefaultsToTCPPlus12), not the former 5569.
func TestSetDefaultsPortsMatchOriginal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enode.config.yaml")
	// No tcp/udp port keys — exercise the defaults only.
	if err := os.WriteFile(path, []byte("address: 127.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: config with no tcp/udp port keys")
	t.Logf("output: tcp=%d/%d udp=%d/%d",
		cfg.TCP.Port, cfg.TCP.PortObfuscated, cfg.UDP.Port, cfg.UDP.PortObfuscated)

	if cfg.TCP.Port != 5555 || cfg.TCP.PortObfuscated != 5565 {
		t.Fatalf("tcp defaults = %d/%d, want 5555/5565", cfg.TCP.Port, cfg.TCP.PortObfuscated)
	}
	if cfg.UDP.Port != 5559 || cfg.UDP.PortObfuscated != 5567 {
		t.Fatalf("udp defaults = %d/%d, want 5559/5567", cfg.UDP.Port, cfg.UDP.PortObfuscated)
	}
}
