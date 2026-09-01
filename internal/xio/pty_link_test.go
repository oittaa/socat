//go:build linux || darwin

package xio

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestCreatePtySlaveLinkRemovesOwnSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "link")
	spec, err := parse.ParseSpec("PTY,link=" + path)
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := CreatePtySlaveLink(spec, "/dev/pts/0")
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("not a symlink")
	}
	cleanup()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("own symlink survived cleanup: %v", err)
	}
}

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

func TestCreatePtySlaveLinkSignalSweepPreservesReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "link")
	spec, err := parse.ParseSpec("PTY,link=" + path)
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := CreatePtySlaveLink(spec, "/dev/pts/0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	replaceAtPath(t, path, []byte("replacement"), 0o600)
	UnlinkRegisteredPaths()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("signal sweep removed replacement: %v", err)
	}
	if string(got) != "replacement" {
		t.Fatalf("contents=%q", got)
	}
}

func TestCreatePtySlaveLinkDoesNotRemoveDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "emptydir")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("PTY,link=" + dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = CreatePtySlaveLink(spec, "/dev/pts/0")
	if err == nil {
		t.Fatal("expected directory link= to fail")
	}
	fi, statErr := os.Lstat(dir)
	if statErr != nil {
		t.Fatalf("directory was removed: %v", statErr)
	}
	if !fi.IsDir() {
		t.Fatalf("mode=%v want directory", fi.Mode())
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
