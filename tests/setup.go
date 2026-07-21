// Package tests holds helpers shared across the project's test suites. It imports
// nothing else in this module, so any package may depend on it without risking an
// import cycle.
package tests

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// FixRelativeTestingPath resolves a repository-root-relative path so it works no
// matter which package directory `go test` runs from.
//
// Tests run with the working directory set to the package under test — storage/,
// config/, ed2k/, cmd/enode/, and so on — so a bare "misc/enode.sql" only resolves
// for a binary started from the project root. This walks up from the working
// directory to the module root (the directory containing go.mod) and returns the
// target relative to the current directory, keeping the relative-path contract of
// the original helper this is modeled on while replacing its hardcoded per-package
// dirname list with root discovery that also handles nested packages like cmd/enode.
//
// An absolute input is returned unchanged. If the root cannot be found or a
// relative form cannot be computed, the closest usable path is returned rather than
// failing, so a caller in an unexpected layout still gets something to try.
func FixRelativeTestingPath(pathStr string) string {
	if filepath.IsAbs(pathStr) {
		return pathStr
	}
	if runtime.GOOS == "windows" {
		pathStr = strings.ReplaceAll(pathStr, "/", "\\")
	}

	root, err := projectRoot()
	if err != nil {
		return pathStr
	}
	abs := filepath.Join(root, pathStr)

	cwd, err := os.Getwd()
	if err != nil {
		return abs
	}
	if rel, err := filepath.Rel(cwd, abs); err == nil {
		return rel
	}
	return abs
}

// SchemaPath resolves the MySQL DDL file (misc/enode.sql) from any package, for
// tests that let storage.MySQLEngine.Init create its tables on first connect.
func SchemaPath() string {
	return FixRelativeTestingPath(filepath.Join("misc", "enode.sql"))
}

// projectRoot walks up from the working directory to the first directory that
// contains a go.mod file, which is the module root.
func projectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
