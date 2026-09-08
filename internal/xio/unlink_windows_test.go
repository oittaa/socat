//go:build windows

package xio

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnlinkRemovesReadOnlyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := Unlink(path); err != nil {
		t.Fatalf("Unlink read-only file: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("read-only file survived Unlink: %v", err)
	}
}

func TestUnlinkRefusesEmptyDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "emptydir")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Unlink(path); err == nil {
		t.Fatal("Unlink removed an empty directory")
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatalf("empty directory was replaced; mode=%v", info.Mode())
	}
}
