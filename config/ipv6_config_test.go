package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "enode.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestIPv6DefaultsEnabledAndKeepsWildcardBind(t *testing.T) {
	// Empty address + IPv6 omitted (defaults on) must stay "" so the listener binds
	// the dual-stack wildcard rather than the IPv4-only 0.0.0.0.
	cfg, err := Load(writeTempConfig(t, "name: t\naddress: \"\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.IPv6.EnabledOrDefault() {
		t.Fatal("IPv6 should default to enabled")
	}
	if cfg.Address != "" {
		t.Fatalf("dual-stack default should keep empty bind, got %q", cfg.Address)
	}
	if !cfg.IPv6.PublishSourcesOrDefault() || !cfg.IPv6.ProbeReachabilityOrDefault() {
		t.Fatal("publishSources and probeReachability should default to true")
	}
	if len(cfg.IPv6.TestURLs6) == 0 {
		t.Fatal("testUrls6 should be seeded by default")
	}
	t.Logf("address=%q ipv6.enabled=%v testUrls6=%d", cfg.Address, cfg.IPv6.EnabledOrDefault(), len(cfg.IPv6.TestURLs6))
}

func TestIPv6DisabledForcesIPv4Wildcard(t *testing.T) {
	// With IPv6 explicitly disabled, an empty bind pins to 0.0.0.0 exactly as before.
	cfg, err := Load(writeTempConfig(t, "name: t\naddress: \"\"\nipv6:\n  enabled: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IPv6.EnabledOrDefault() {
		t.Fatal("IPv6 should be disabled")
	}
	if cfg.Address != "0.0.0.0" {
		t.Fatalf("IPv6-disabled empty bind should become 0.0.0.0, got %q", cfg.Address)
	}
	t.Logf("ipv6 disabled -> address=%q", cfg.Address)
}

func TestIPv6ExplicitBindHonoured(t *testing.T) {
	cfg, err := Load(writeTempConfig(t, "name: t\naddress: \"127.0.0.1\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Address != "127.0.0.1" {
		t.Fatalf("explicit bind must be honoured, got %q", cfg.Address)
	}
	t.Logf("explicit IPv4 bind stays %q with ipv6.enabled=%v", cfg.Address, cfg.IPv6.EnabledOrDefault())
}
