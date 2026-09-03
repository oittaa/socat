//go:build linux

package relay

import (
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestWaitReadableAndWritableFIFOReconnectAfterHangup covers a writer that
// disconnects (POLLHUP), reconnects before the 0-timeout confirmation poll,
// then writes. Omission must follow confirmed state, not the stale hangup.
// Linux-only: Darwin FIFO poll follows buffered byte count and does not
// report POLLHUP when the last writer closes an empty FIFO.
func TestWaitReadableAndWritableFIFOReconnectAfterHangup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reopen.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Skipf("FIFO reader: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })
	srcFD := fileFD(t, src)
	_, dstW := pipePair(t)
	dstFD := fileFD(t, dstW)

	var writer *os.File
	t.Cleanup(func() {
		if writer != nil {
			_ = writer.Close()
		}
	})

	sawHUP := make(chan struct{})
	var sawOnce sync.Once
	resume := make(chan struct{})
	release := onceClose(resume)
	rearmed := make(chan struct{})
	var rearmOnce sync.Once
	var afterHUP atomic.Bool

	hook := func(fds []unix.PollFd, timeoutMs int) (int, error) {
		if afterHUP.Load() {
			rearmOnce.Do(func() { close(rearmed) })
		}
		n, err := poll(fds, timeoutMs)
		if err == nil && n > 0 && !afterHUP.Load() {
			for _, fd := range fds {
				if fd.Fd == int32(srcFD) && fd.Revents&pollHup != 0 {
					sawOnce.Do(func() { close(sawHUP) })
					<-resume
					afterHUP.Store(true)
					break
				}
			}
		}
		return n, err
	}
	done := startHookedWait(t, srcFD, dstFD, hook, 2*time.Second, release)

	w, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case <-sawHUP:
	case err := <-done:
		t.Skipf("FIFO hangup did not stay in waitReadableAndWritable: %v", err)
	case <-time.After(time.Second):
		t.Fatal("waiting poll did not observe FIFO POLLHUP")
	}

	writer, err = os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	release()

	select {
	case <-rearmed:
	case err := <-done:
		t.Fatalf("wait returned before reconnect write: %v", err)
	case <-time.After(time.Second):
		t.Fatal("did not re-enter wait poll after FIFO reconnect")
	}

	if _, err := writer.Write([]byte("go")); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("after FIFO reconnect: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("source stayed omitted after FIFO writer reconnected")
	}

	got := make([]byte, 2)
	if _, err := io.ReadFull(src, got); err != nil {
		t.Fatalf("source consumed or unread: %v", err)
	}
	if string(got) != "go" {
		t.Fatalf("source=%q want go", got)
	}
}
