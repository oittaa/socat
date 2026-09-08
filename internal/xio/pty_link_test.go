//go:build linux || darwin

package xio

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestCreatePtySlaveLinkPreservesReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "link")
	spec, err := parse.ParseSpec("PTY,link=" + path)
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := CreatePtySlaveLink(spec, "/dev/pts/0")
	if err != nil {
		t.Fatal(err)
	}
	replaceAtPath(t, path, []byte("replacement"), 0o600)
	cleanup()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("replacement path was removed: %v", err)
	}
	if string(got) != "replacement" {
		t.Fatalf("contents=%q", got)
	}
}

func TestCreatePtySlaveLinkHonorsUnlinkCloseFalse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "link")
	spec, err := parse.ParseSpec("PTY,link=" + path + ",unlink-close=0")
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := CreatePtySlaveLink(spec, "/dev/pts/0")
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	UnlinkRegisteredPaths()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("unlink-close=0 removed link: %v", err)
	}
}

func TestCreatePtySlaveLinkRequiresPath(t *testing.T) {
	spec, err := parse.ParseSpec("PTY,link")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreatePtySlaveLink(spec, "/dev/pts/0"); err == nil {
		t.Fatal("expected empty link= to fail")
	}
}
