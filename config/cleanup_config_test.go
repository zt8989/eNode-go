package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, body string) Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "enode.config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// keepZeroSourceFiles must default to *true* when the key is absent.
//
// This is the reason the field is a *bool. A plain bool unmarshals to false for
// a missing key, which is indistinguishable from an explicit false — so every
// config written before this option existed would silently start deleting files.
// A plain-bool implementation passes every other test in this file and fails
// only this one.
func TestKeepZeroSourceFilesDefaultsToTrue(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want bool
	}{
		{
			"the key is absent entirely",
			"address: 127.0.0.1\nstorage:\n  engine: memory\n",
			true,
		},
		{
			"the cleanup block exists but omits the key",
			"address: 127.0.0.1\nstorage:\n  engine: memory\n  cleanup:\n    enabled: true\n",
			true,
		},
		{
			"explicitly true",
			"address: 127.0.0.1\nstorage:\n  engine: memory\n  cleanup:\n    keepZeroSourceFiles: true\n",
			true,
		},
		{
			"explicitly false is honoured",
			"address: 127.0.0.1\nstorage:\n  engine: memory\n  cleanup:\n    keepZeroSourceFiles: false\n",
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := writeConfig(t, tc.yaml)
			got := cfg.Storage.Cleanup.KeepZeroSourceFilesOrDefault()
			t.Logf("input: %q", tc.yaml)
			t.Logf("output: keepZeroSourceFiles=%t (pointer set=%t)", got, cfg.Storage.Cleanup.KeepZeroSourceFiles != nil)
			if got != tc.want {
				t.Fatalf("got %t, want %t", got, tc.want)
			}
		})
	}
}

func TestCleanupConfigDefaults(t *testing.T) {
	cfg := writeConfig(t, "address: 127.0.0.1\nstorage:\n  engine: memory\n")
	t.Logf("output: staleAfterHours=%d intervalMinutes=%d enabled=%t",
		cfg.Storage.Cleanup.StaleAfterHours, cfg.Storage.Cleanup.IntervalMinutes, cfg.Storage.Cleanup.Enabled)

	if cfg.Storage.Cleanup.StaleAfterHours != 24 {
		t.Fatalf("staleAfterHours=%d, want 24", cfg.Storage.Cleanup.StaleAfterHours)
	}
	if cfg.Storage.Cleanup.IntervalMinutes != 60 {
		t.Fatalf("intervalMinutes=%d, want 60", cfg.Storage.Cleanup.IntervalMinutes)
	}
	// Enabled deliberately stays false when unset: a sweep that deletes rows
	// should be opted into, not inherited by an existing deployment on upgrade.
	if cfg.Storage.Cleanup.Enabled {
		t.Fatal("cleanup defaulted to enabled")
	}
}

func TestCleanupConfigExplicitValues(t *testing.T) {
	cfg := writeConfig(t, `
address: 127.0.0.1
storage:
  engine: memory
  cleanup:
    enabled: true
    staleAfterHours: 6
    intervalMinutes: 15
    batchSize: 250
`)
	t.Logf("output: enabled=%t staleAfterHours=%d intervalMinutes=%d batchSize=%d",
		cfg.Storage.Cleanup.Enabled, cfg.Storage.Cleanup.StaleAfterHours,
		cfg.Storage.Cleanup.IntervalMinutes, cfg.Storage.Cleanup.BatchSize)

	if !cfg.Storage.Cleanup.Enabled ||
		cfg.Storage.Cleanup.StaleAfterHours != 6 ||
		cfg.Storage.Cleanup.IntervalMinutes != 15 ||
		cfg.Storage.Cleanup.BatchSize != 250 {
		t.Fatal("explicit cleanup values were not preserved")
	}
}
