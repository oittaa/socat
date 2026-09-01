package netopen

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestUnixBindCreatedUnlinkRemovesOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "created")
	if err := os.WriteFile(path, []byte("created"), 0o600); err != nil {
		t.Fatal(err)
	}
	rememberUnixBindCreated(path).unlink()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("created path survived unlink: %v", err)
	}
}

func TestUnixBindCreatedUnlinkPreservesReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "created")
	if err := os.WriteFile(path, []byte("created"), 0o600); err != nil {
		t.Fatal(err)
	}
	created := rememberUnixBindCreated(path)
	// Keep the original inode alive so a recycled directory-entry number cannot
	// make SameFile true. Windows refuses to remove an open file.
	if runtime.GOOS != "windows" {
		original, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = original.Close() })
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	created.unlink()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("replacement path was removed: %v", err)
	}
	if string(got) != "replacement" {
		t.Fatalf("replacement contents=%q", got)
	}
}
