package xio

import (
	"os"
	"path/filepath"
	"testing"
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
