package config

import "testing"

func TestNATIPv6DefaultsEnabled(t *testing.T) {
	// natTraversal.ipv6 omitted must default to true (the *bool absent-key pattern).
	cfg, err := Load(writeTempConfig(t, "name: t\nnatTraversal:\n  enabled: true\n  port: 2004\n"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("natTraversal.ipv6 omitted -> IPv6OrDefault()=%v", cfg.NAT.IPv6OrDefault())
	if !cfg.NAT.IPv6OrDefault() {
		t.Fatal("natTraversal.ipv6 should default to enabled")
	}
}

func TestNATIPv6HonoursExplicitFalse(t *testing.T) {
	cfg, err := Load(writeTempConfig(t, "name: t\nnatTraversal:\n  enabled: true\n  port: 2004\n  ipv6: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("natTraversal.ipv6: false -> IPv6OrDefault()=%v", cfg.NAT.IPv6OrDefault())
	if cfg.NAT.IPv6OrDefault() {
		t.Fatal("natTraversal.ipv6: false must disable IPv6 hole-punching")
	}
}

func TestNATServerIndependentDefaultsEnabled(t *testing.T) {
	// natTraversal.serverIndependent omitted must default to true.
	cfg, err := Load(writeTempConfig(t, "name: t\nnatTraversal:\n  enabled: true\n  port: 2004\n"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("natTraversal.serverIndependent omitted -> ServerIndependentOrDefault()=%v", cfg.NAT.ServerIndependentOrDefault())
	if !cfg.NAT.ServerIndependentOrDefault() {
		t.Fatal("natTraversal.serverIndependent should default to enabled")
	}
}

func TestNATServerIndependentHonoursExplicitFalse(t *testing.T) {
	cfg, err := Load(writeTempConfig(t, "name: t\nnatTraversal:\n  enabled: true\n  port: 2004\n  serverIndependent: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("natTraversal.serverIndependent: false -> ServerIndependentOrDefault()=%v", cfg.NAT.ServerIndependentOrDefault())
	if cfg.NAT.ServerIndependentOrDefault() {
		t.Fatal("natTraversal.serverIndependent: false must restrict rendezvous to logged-in clients")
	}
}
