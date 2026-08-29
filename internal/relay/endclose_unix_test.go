//go:build linux || darwin

package relay

import (
	"context"
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"
	"time"
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

func socketpairStream(f *os.File) Stream {
	return RWCStream{ReadWriteCloser: f}
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

func TestSessionWrapShutdownWriteKeepsSocketpairOpen(t *testing.T) {
	parent, child := unixSocketpair(t)
	first := newSessionWrap(socketpairStream(parent))
	if err := first.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	sess := newSessionWrap(socketpairStream(parent))
	if _, err := sess.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	n, err := child.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("got %q", buf[:n])
	}
}

func TestSessionWrapReusesSocketpairAfterClosePoke(t *testing.T) {
	parent, child := unixSocketpair(t)
	inner := socketpairStream(parent)
	if err := newSessionWrap(inner).Close(); err != nil {
		t.Fatal(err)
	}
	sess := newSessionWrap(inner)
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		n, err := sess.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		if string(buf[:n]) != "hello" {
			errCh <- fmt.Errorf("got %q", buf[:n])
			return
		}
		errCh <- nil
	}()
	if _, err := child.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("second session read: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second session did not read")
	}
}

func TestTransferEndCloseReusesSharedSocketpair(t *testing.T) {
	parent, child := unixSocketpair(t)
	left := socketpairStream(parent)
	for _, message := range []string{"first", "second"} {
		right := FDStream{
			R:      &oneShotReader{data: []byte(message)},
			W:      io.Discard,
			C:      nopCloser{},
			CloseW: func() error { return nil },
		}
		done := make(chan error, 1)
		go func() {
			done <- Transfer(context.Background(), left, right, Config{
				RightToLeft: true,
				NoCloseLeft: true,
			})
		}()
		buf := make([]byte, len(message))
		if _, err := io.ReadFull(child, buf); err != nil {
			t.Fatalf("read %q: %v", message, err)
		}
		if string(buf) != message {
			t.Fatalf("got %q, want %q", buf, message)
		}
		if err := <-done; err != nil {
			t.Fatalf("transfer %q: %v", message, err)
		}
	}
}
