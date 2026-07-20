package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// deadlockDelay was parsed from YAML into MySQLConfig and then dropped by
// StorageEngineConfig, which never copied it into storage.MySQLConfig — so the
// option was inert no matter what the operator set. Asserting the parsed struct
// alone would not have caught that; the check has to follow the value across the
// config-to-storage boundary.
func TestStorageEngineConfigCarriesDeadlockDelay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enode.config.yaml")
	err := os.WriteFile(path, []byte(`
address: 127.0.0.1
storage:
  engine: mysql
  mysql:
    host: localhost
    port: 3306
    user: enode
    pass: password
    database: enode
    deadlockDelay: 250
`), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: deadlockDelay: 250 (ms) in YAML")
	t.Logf("output: parsed config value=%d", cfg.Storage.MySQL.DeadlockDelay)

	if cfg.Storage.MySQL.DeadlockDelay != 250 {
		t.Fatalf("parsed DeadlockDelay=%d, want 250", cfg.Storage.MySQL.DeadlockDelay)
	}

	storageCfg := cfg.StorageEngineConfig()
	t.Logf("output: storage.MySQLConfig.DeadlockDelay=%s", storageCfg.MySQL.DeadlockDelay)

	if storageCfg.MySQL.DeadlockDelay != 250*time.Millisecond {
		t.Fatalf("storage DeadlockDelay=%s, want 250ms — the value is dropped at the config boundary",
			storageCfg.MySQL.DeadlockDelay)
	}
}
