//go:build unix

package xio

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestUnlinkRegistryDoesNotRemoveReplacementFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(path, 0o666); err != nil {
		t.Fatal(err)
	}
	unregister := RegisterUnlinkPath(path)
	t.Cleanup(unregister)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o666); err != nil {
		t.Fatal(err)
	}

	UnlinkRegisteredPaths()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("replacement FIFO was removed: %v", err)
	}
}
