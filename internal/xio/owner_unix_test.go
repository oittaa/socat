//go:build linux || darwin

package xio

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestUnlinkRegistryDoesNotRemoveReplacementFIFO(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(path, 0o666); err != nil {
		t.Fatal(err)
	}
	unregister := RegisterUnlinkPath(path)
	t.Cleanup(unregister)

	other := filepath.Join(dir, "other")
	if err := syscall.Mkfifo(other, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, path); err != nil {
		t.Fatal(err)
	}

	UnlinkRegisteredPaths()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("replacement FIFO was removed: %v", err)
	}
}

func TestRegisterUnlinkPathDoesNotBlockOnFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(path, 0o666); err != nil {
		t.Fatal(err)
	}
	done := make(chan func(), 1)
	go func() {
		done <- RegisterUnlinkPath(path)
	}()
	select {
	case unregister := <-done:
		t.Cleanup(unregister)
	case <-time.After(2 * time.Second):
		t.Fatal("RegisterUnlinkPath blocked opening a FIFO with no writer")
	}

	UnlinkRegisteredPaths()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("FIFO survived signal sweep: %v", err)
	}
}
