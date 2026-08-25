package xio

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUnlinkRegistryDoesNotRemoveReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	unregister := RegisterUnlinkPath(path)
	t.Cleanup(unregister)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}

	UnlinkRegisteredPaths()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("replacement was removed: %v", err)
	}
	if string(got) != "replacement" {
		t.Fatalf("contents=%q", got)
	}
}

func TestUnlinkRegistryDoesNotRemoveSameSizeReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	unregister := RegisterUnlinkPath(path)
	t.Cleanup(unregister)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// Same length as "original" so size/mtime matching cannot distinguish a
	// recycled inode from the object we registered.
	if err := os.WriteFile(path, []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatal(err)
	}

	UnlinkRegisteredPaths()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("same-size replacement was removed: %v", err)
	}
	if string(got) != "ORIGINAL" {
		t.Fatalf("contents=%q", got)
	}
}

func TestUnlinkRegistryRemovesAfterMetadataChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint")
	if err := os.WriteFile(path, []byte("keep-me-not"), 0o600); err != nil {
		t.Fatal(err)
	}
	unregister := RegisterUnlinkPath(path)
	t.Cleanup(unregister)
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	UnlinkRegisteredPaths()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("registered path survived metadata change: %v", err)
	}
}

func TestUnlinkRegistryUnregistersClosedEndpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	unregister := RegisterUnlinkPath(path)
	unregister()
	UnlinkRegisteredPaths()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("unregistered path was removed: %v", err)
	}
}
