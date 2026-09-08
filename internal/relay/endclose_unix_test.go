//go:build linux || darwin

package relay

import (
	"io"
	"os"
	"syscall"
	"testing"
)

func unixSocketpair(t *testing.T) (parent, child *os.File) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent = os.NewFile(uintptr(fds[0]), "session-parent")
	child = os.NewFile(uintptr(fds[1]), "session-child")
	t.Cleanup(func() {
		_ = parent.Close()
		_ = child.Close()
	})
	return parent, child
}

// TestSocketpairShutdownWritePreventsReuse is the shared-FD race that
// EXEC,end-close + LISTEN,fork would hit if a session half-closed the
// socketpair. shutdown(SHUT_WR) is process-wide; later writes fail and the
// peer sees EOF. runForkListenRight therefore uses sessionWrap (no
// ShutdownWrite) and leftMu so sessions do not call this.
func TestSocketpairShutdownWritePreventsReuse(t *testing.T) {
	parent, child := unixSocketpair(t)
	if err := syscall.Shutdown(int(parent.Fd()), syscall.SHUT_WR); err != nil {
		t.Fatal(err)
	}
	if _, err := parent.Write([]byte("second")); err == nil {
		t.Fatal("write after SHUT_WR succeeded")
	}
	buf := make([]byte, 8)
	n, err := child.Read(buf)
	if n != 0 || err != io.EOF {
		t.Fatalf("peer after SHUT_WR: n=%d err=%v want EOF", n, err)
	}
}
