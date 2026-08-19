//go:build unix

package fileopen

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestApplyFileLocksUsesMatchingDescriptorAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locked")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	readOnly, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()

	readLock, err := parse.ParseSpec("OPEN:" + path + ",setlk-rd")
	if err != nil {
		t.Fatal(err)
	}
	if err := applyFileLocks(readLock, readOnly, nil); err != nil {
		t.Fatalf("read lock on read descriptor: %v", err)
	}

	writeLock, err := parse.ParseSpec("OPEN:" + path + ",setlk")
	if err != nil {
		t.Fatal(err)
	}
	if err := applyFileLocks(writeLock, nil, readOnly); err == nil {
		t.Fatal("write lock unexpectedly succeeded on a read-only descriptor")
	}
}
