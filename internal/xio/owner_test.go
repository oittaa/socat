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
	replaceAtPath(t, path, []byte("replacement"), 0o600)

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
	// Same length as "original". Unlink+recreate can recycle inode / NTFS
	// file IDs; rename-over keeps both objects alive so SameFile can tell
	// them apart.
	replaceAtPath(t, path, []byte("ORIGINAL"), 0o600)

	UnlinkRegisteredPaths()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("same-size replacement was removed: %v", err)
	}
	if string(got) != "ORIGINAL" {
		t.Fatalf("contents=%q", got)
	}
}

// replaceAtPath installs contents at path by renaming a sibling over it.
func replaceAtPath(t *testing.T, path string, contents []byte, perm os.FileMode) {
	t.Helper()
	other := path + ".new"
	if err := os.WriteFile(other, contents, perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, path); err != nil {
		t.Fatal(err)
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

func TestUnlinkIfSameFilePreservesReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !SnapshotFileIdentity(info) {
		t.Fatal("could not snapshot identity")
	}
	replaceAtPath(t, path, []byte("replacement"), 0o600)
	UnlinkIfSameFile(path, info)
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("replacement was removed: %v", err)
	}
	if string(got) != "replacement" {
		t.Fatalf("contents=%q", got)
	}
}

func TestUnlinkIfSameFileRemovesOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !SnapshotFileIdentity(info) {
		t.Fatal("could not snapshot identity")
	}
	UnlinkIfSameFile(path, info)
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("original survived: %v", err)
	}
}
