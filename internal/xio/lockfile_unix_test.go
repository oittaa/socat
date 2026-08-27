//go:build unix

package xio

import (
	"os"
	"testing"

	"github.com/oittaa/socat/internal/testutil"
	"golang.org/x/sys/unix"
)

func TestCreateLockFileModeIgnoresUmask(t *testing.T) {
	path := testutil.UnixSocketPath(t, "umask.lock")
	old := unix.Umask(0o077)
	t.Cleanup(func() { unix.Umask(old) })
	info, err := CreateLockFile(path)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Fatalf("mode=%o want 0644 under umask 077 (classic fchmod 0644)", st.Mode().Perm())
	}
	if !sameRegisteredFile(info, st) {
		t.Fatal("returned identity does not match the lock pathname")
	}
}
