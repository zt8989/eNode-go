package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSetDefaultsPortsMatchOriginal pins L3: a YAML that omits the port keys must
// fall back to the ports the Node original (enode.config.js) and both shipped
// configs use — TCP 5555/5565, UDP 5559/5569 — not the classic eDonkey
// 4661/4662/4665/4666. Against the pre-fix build TCP.Port is 4661.
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
	if cfg.UDP.Port != 5559 || cfg.UDP.PortObfuscated != 5569 {
		t.Fatalf("udp defaults = %d/%d, want 5559/5569", cfg.UDP.Port, cfg.UDP.PortObfuscated)
	}
}
