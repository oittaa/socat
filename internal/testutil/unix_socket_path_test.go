package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnixSocketPathIsShortAndUnique(t *testing.T) {
	first := UnixSocketPath(t, "listener.sock")
	second := UnixSocketPath(t, "listener.sock")
	if first == second {
		t.Fatalf("paths are not unique: %q", first)
	}
	for _, path := range []string{first, second} {
		if len([]byte(path)) > maxUnixSocketPathBytes {
			t.Fatalf("path is %d bytes, maximum is %d: %q", len([]byte(path)), maxUnixSocketPathBytes, path)
		}
		if filepath.Base(path) != "listener.sock" {
			t.Fatalf("path base=%q want listener.sock", filepath.Base(path))
		}
		if info, err := os.Stat(filepath.Dir(path)); err != nil || !info.IsDir() {
			t.Fatalf("temporary directory is unavailable: info=%v err=%v", info, err)
		}
	}
}
