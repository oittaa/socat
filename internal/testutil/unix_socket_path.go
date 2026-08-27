package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// maxUnixSocketPathBytes stays below Darwin's 104-byte sockaddr_un.sun_path
// limit (including its terminating NUL) and is also safe on Linux and Windows.
const maxUnixSocketPathBytes = 100

// UnixSocketPath returns a short, unique path suitable for a filesystem-backed
// UNIX-domain socket. Unlike testing.TB.TempDir, the directory name does not
// include the test name, which can make socket paths exceed Darwin's sun_path
// limit on CI runners.
func UnixSocketPath(t testing.TB, name string) string {
	t.Helper()
	if name == "" || name == "." || filepath.Base(name) != name {
		t.Fatalf("UNIX socket name %q must be a non-empty base name", name)
	}

	root := os.TempDir()
	if runtime.GOOS != "windows" {
		root = "/tmp"
	}
	dir, err := os.MkdirTemp(root, "s-u-")
	if err != nil {
		t.Fatalf("create UNIX socket test directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove UNIX socket test directory: %v", err)
		}
	})

	path := filepath.Join(dir, name)
	if len([]byte(path)) > maxUnixSocketPathBytes {
		t.Fatalf("UNIX socket test path is %d bytes, maximum is %d: %q", len([]byte(path)), maxUnixSocketPathBytes, path)
	}
	return path
}
