//go:build linux || darwin

package relay

import (
	"context"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestStreamNeedsExplicitPoll(t *testing.T) {
	regular, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = regular.Close() }()
	if streamNeedsExplicitPoll(FDStream{R: regular, W: regular, C: regular}) {
		t.Fatal("regular file unexpectedly requires explicit poll")
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pr.Close() }()
	defer func() { _ = pw.Close() }()
	if !streamNeedsExplicitPoll(FDStream{R: pr, W: pw, C: nopCloser{}}) {
		t.Fatal("pipe must retain explicit poll backpressure")
	}
}

func pipePair(t *testing.T) (r, w *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	return r, w
}

func fileFD(t *testing.T, f *os.File) int {
	t.Helper()
	fd := int(f.Fd())
	if fd < 0 {
		t.Fatal("closed fd")
	}
	return fd
}

func countingPollWait(t *testing.T) *atomic.Int32 {
	t.Helper()
	orig := pollWait
	var n atomic.Int32
	pollWait = func(fds []unix.PollFd, timeoutMs int) (int, error) {
		n.Add(1)
		return poll(fds, timeoutMs)
	}
	t.Cleanup(func() { pollWait = orig })
	return &n
}

func waitPollWithTimeout(t *testing.T, srcFD, dstFD int, d time.Duration) (polls int32, err error) {
	t.Helper()
	n := countingPollWait(t)
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	err = waitReadableAndWritable(ctx, srcFD, dstFD)
	return n.Load(), err
}

// startHookedWait runs waitReadableAndWritable in a worker with pollWait
// replaced. Every test exit path releases optional gates, cancels, joins the
// worker, then restores pollWait before later cleanups close its descriptors.
func startHookedWait(t *testing.T, srcFD, dstFD int, hook func([]unix.PollFd, int) (int, error), d time.Duration, release ...func()) <-chan error {
	t.Helper()
	orig := pollWait
	pollWait = hook
	ctx, cancel := context.WithTimeout(context.Background(), d)
	done := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		done <- waitReadableAndWritable(ctx, srcFD, dstFD)
	}()
	t.Cleanup(func() {
		for _, r := range release {
			if r != nil {
				r()
			}
		}
		cancel()
		wg.Wait()
		pollWait = orig
	})
	return done
}

type ownedFD struct {
	fd    int
	owned atomic.Bool
}

func newOwnedFD(t *testing.T, fd int) *ownedFD {
	t.Helper()
	o := &ownedFD{fd: fd}
	o.owned.Store(true)
	t.Cleanup(func() {
		if o.owned.Swap(false) {
			_ = unix.Close(o.fd)
		}
	})
	return o
}

func (o *ownedFD) closeNow(t *testing.T) {
	t.Helper()
	if !o.owned.Swap(false) {
		return
	}
	if err := unix.Close(o.fd); err != nil {
		t.Fatal(err)
	}
}

// darwinZeroEventPollWait models Darwin poll: Events=0 registers no kqueue
// filter, so those entries never wake the waiting poll.
func darwinZeroEventPollWait(fds []unix.PollFd, timeoutMs int) (int, error) {
	filtered := make([]unix.PollFd, 0, len(fds))
	pos := make([]int, 0, len(fds))
	for i := range fds {
		fds[i].Revents = 0
		if fds[i].Events == 0 {
			continue
		}
		filtered = append(filtered, fds[i])
		pos = append(pos, i)
	}
	if len(filtered) == 0 {
		_, err := poll(nil, timeoutMs)
		return 0, err
	}
	n, err := poll(filtered, timeoutMs)
	for i, p := range pos {
		fds[p].Revents = filtered[i].Revents
	}
	return n, err
}

func onceClose(ch chan struct{}) func() {
	var once sync.Once
	return func() { once.Do(func() { close(ch) }) }
}

// runMaskedDestCloseAfterReady waits until destination is masked (Events=0
// because it is already writable), then closes the polled destination fd.
func runMaskedDestCloseAfterReady(t *testing.T, wait func([]unix.PollFd, int) (int, error)) {
	t.Helper()
	srcR, _ := pipePair(t)
	_, dstW := pipePair(t)
	nval, err := unix.Dup(int(dstW.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	owned := newOwnedFD(t, nval)
	srcFD := fileFD(t, srcR)
	dstFD := nval

	masked := make(chan struct{})
	var maskOnce sync.Once
	proceed := make(chan struct{})
	release := onceClose(proceed)

	hook := func(fds []unix.PollFd, timeoutMs int) (int, error) {
		for _, fd := range fds {
			if fd.Fd == int32(dstFD) && fd.Events == 0 {
				maskOnce.Do(func() { close(masked) })
				<-proceed
				break
			}
		}
		return wait(fds, timeoutMs)
	}
	done := startHookedWait(t, srcFD, dstFD, hook, 2*time.Second, release)

	select {
	case <-masked:
	case err := <-done:
		t.Fatalf("wait returned before destination was masked: %v", err)
	case <-time.After(time.Second):
		t.Fatal("destination never entered Events=0 wait")
	}

	owned.closeNow(t)
	closedAt := time.Now()
	release()

	select {
	case err := <-done:
		if err != io.ErrClosedPipe {
			t.Fatalf("masked dest close err=%v want closed pipe", err)
		}
		if d := time.Since(closedAt); d > 500*time.Millisecond {
			t.Fatalf("masked dest close took %v, want observation within one wait-timeout interval", d)
		}
	case <-time.After(time.Second):
		t.Fatal("masked destination close was not observed")
	}
}

// maxOneSidedPolls is well above a 100ms-timeout wait over 300ms (~3–4 polls)
// and far below a busy-spin (tens of thousands).
const maxOneSidedPolls = 20

func TestWaitReadableAndWritableIdleSourceDoesNotSpin(t *testing.T) {
	srcR, _ := pipePair(t)
	_, dstW := pipePair(t)

	n, err := waitPollWithTimeout(t, fileFD(t, srcR), fileFD(t, dstW), 300*time.Millisecond)
	if err == nil {
		t.Fatal("idle source returned as ready")
	}
	if err != context.DeadlineExceeded {
		t.Fatalf("err=%v want deadline exceeded", err)
	}
	if n > maxOneSidedPolls {
		t.Fatalf("polls=%d want <= %d (busy-spin)", n, maxOneSidedPolls)
	}
	if n < 1 {
		t.Fatal("poll was never called")
	}
}

func TestWaitReadableAndWritableBothReady(t *testing.T) {
	srcR, srcW := pipePair(t)
	_, dstW := pipePair(t)
	if _, err := srcW.Write([]byte("xy")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitReadableAndWritable(ctx, fileFD(t, srcR), fileFD(t, dstW)); err != nil {
		t.Fatal(err)
	}
}

func TestWaitReadableAndWritableCancel(t *testing.T) {
	srcR, _ := pipePair(t)
	_, dstW := pipePair(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- waitReadableAndWritable(ctx, fileFD(t, srcR), fileFD(t, dstW))
	}()
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("err=%v want canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("did not return on cancel")
	}
}

func TestWaitReadableAndWritableSourceHangup(t *testing.T) {
	srcR, srcW := pipePair(t)
	_, dstW := pipePair(t)
	if err := srcW.Close(); err != nil {
		t.Fatal(err)
	}

	n, err := waitPollWithTimeout(t, fileFD(t, srcR), fileFD(t, dstW), time.Second)
	if err != nil {
		t.Fatalf("source hangup: %v", err)
	}
	if n > maxOneSidedPolls {
		t.Fatalf("polls=%d want <= %d (busy-spin)", n, maxOneSidedPolls)
	}
}

func TestWaitReadableAndWritableIdleSourceDestHangupDoesNotSpin(t *testing.T) {
	srcR, _ := pipePair(t)
	dstR, dstW := pipePair(t)
	if err := dstR.Close(); err != nil {
		t.Fatal(err)
	}

	n, err := waitPollWithTimeout(t, fileFD(t, srcR), fileFD(t, dstW), 300*time.Millisecond)
	if err != nil && err != io.ErrClosedPipe && err != context.DeadlineExceeded {
		t.Fatalf("err=%v", err)
	}
	if n > maxOneSidedPolls {
		t.Fatalf("polls=%d want <= %d (busy-spin)", n, maxOneSidedPolls)
	}
}

func TestWaitReadableAndWritableInvalidFD(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitReadableAndWritable(ctx, -1, -1); err != unix.EBADF {
		t.Fatalf("err=%v want EBADF", err)
	}
}

// TestWaitReadableAndWritableMaskedDestCloseDarwinModel closes the destination
// after it has been masked (Events=0). The waiting poll hides Events=0 the
// way Darwin does, so timeout confirmation must observe the closed fd.
func TestWaitReadableAndWritableMaskedDestCloseDarwinModel(t *testing.T) {
	runMaskedDestCloseAfterReady(t, darwinZeroEventPollWait)
}
