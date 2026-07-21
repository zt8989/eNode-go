package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enode/storage"
)

// TestDialectDefaultsToMariaDB pins the default: a YAML that omits
// storage.mysql.dialect must fall back to the portable word-based dialect, not
// an empty string. Against a build with the default removed this is "".
func TestDialectDefaultsToMariaDB(t *testing.T) {
	path := writeDialectConfig(t, "") // no dialect key at all
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: config with no storage.mysql.dialect key")
	t.Logf("output: dialect=%q", cfg.Storage.MySQL.Dialect)
	if cfg.Storage.MySQL.Dialect != storage.DialectMariaDB {
		t.Fatalf("default dialect = %q, want %q", cfg.Storage.MySQL.Dialect, storage.DialectMariaDB)
	}
}

// TestDialectMySQLPreserved confirms an explicit dialect survives defaulting.
func TestDialectMySQLPreserved(t *testing.T) {
	path := writeDialectConfig(t, "    dialect: mysql\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input: storage.mysql.dialect = mysql")
	t.Logf("output: dialect=%q", cfg.Storage.MySQL.Dialect)
	if cfg.Storage.MySQL.Dialect != storage.DialectMySQL {
		t.Fatalf("dialect = %q, want %q", cfg.Storage.MySQL.Dialect, storage.DialectMySQL)
	}
}

// TestDialectRejectsUnknown pins the fail-fast validation: an unrecognised
// dialect is a load error, not a silent fallback to some strategy the operator
// did not choose.
func TestDialectRejectsUnknown(t *testing.T) {
	path := writeDialectConfig(t, "    dialect: postgres\n")
	_, err := Load(path)
	t.Logf("input: storage.mysql.dialect = postgres")
	t.Logf("output: err=%v", err)
	if err == nil {
		t.Fatal("Load accepted an invalid dialect, want an error")
	}
	if !strings.Contains(err.Error(), "dialect") {
		t.Fatalf("error %q does not mention the dialect field", err)
	}
}

func writeDialectConfig(t *testing.T, mysqlDialectLine string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "enode.config.yaml")
	body := "address: 127.0.0.1\nstorage:\n  engine: memory\n  mysql:\n    database: enode\n" + mysqlDialectLine
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
