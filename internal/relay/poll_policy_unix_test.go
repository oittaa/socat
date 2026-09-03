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

func TestExplicitPollDoesNotConsumeSourceWhenDestinationStalls(t *testing.T) {
	srcR, srcW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srcR.Close() }()
	defer func() { _ = srcW.Close() }()
	dstR, dstW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dstR.Close() }()
	defer func() { _ = dstW.Close() }()
	fillPipeForPollTest(t, dstW)

	payload := []byte("must remain unread")
	if _, err := srcW.Write(payload); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Transfer(ctx,
			FDStream{R: srcR, W: io.Discard, C: nopCloser{}},
			FDStream{R: eofReader{}, W: dstW, C: nopCloser{}},
			Config{BufferSize: len(payload), LeftToRight: true},
		)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("transfer did not stop while destination was stalled")
	}

	_ = srcR.SetReadDeadline(time.Time{})
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(srcR, got); err != nil {
		t.Fatalf("source was consumed before destination became writable: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("source=%q want %q", got, payload)
	}
}

func fillPipeForPollTest(t *testing.T, pipe *os.File) {
	t.Helper()
	raw, err := pipe.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fillErr error
	if err := raw.Control(func(fd uintptr) {
		flags, err := unix.FcntlInt(fd, unix.F_GETFL, 0)
		if err != nil {
			fillErr = err
			return
		}
		if _, err := unix.FcntlInt(fd, unix.F_SETFL, flags|unix.O_NONBLOCK); err != nil {
			fillErr = err
			return
		}
		defer func() {
			if _, err := unix.FcntlInt(fd, unix.F_SETFL, flags); fillErr == nil {
				fillErr = err
			}
		}()
		buf := make([]byte, 64<<10)
		for {
			if _, err := unix.Write(int(fd), buf); err != nil {
				if err != unix.EAGAIN && err != unix.EWOULDBLOCK {
					fillErr = err
				}
				return
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	if fillErr != nil {
		t.Fatal(fillErr)
	}
}

// nvalDest is a write endpoint whose poll fd is already closed. Darwin
// socketpair HUP after an EXEC child exits looks the same: POLLHUP/POLLNVAL
// without POLLOUT, so waitReadableAndWritable returns ErrClosedPipe.
type nvalDest int

func (d nvalDest) Fd() uintptr { return uintptr(d) }

func (d nvalDest) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

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

func TestWaitReadableAndWritableBlockedDestDoesNotSpin(t *testing.T) {
	srcR, srcW := pipePair(t)
	_, dstW := pipePair(t)
	fillPipeForPollTest(t, dstW)
	payload := []byte("unread")
	if _, err := srcW.Write(payload); err != nil {
		t.Fatal(err)
	}

	n, err := waitPollWithTimeout(t, fileFD(t, srcR), fileFD(t, dstW), 300*time.Millisecond)
	if err == nil {
		t.Fatal("blocked destination returned as ready")
	}
	if err != context.DeadlineExceeded {
		t.Fatalf("err=%v want deadline exceeded", err)
	}
	if n > maxOneSidedPolls {
		t.Fatalf("polls=%d want <= %d (busy-spin)", n, maxOneSidedPolls)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(srcR, got); err != nil {
		t.Fatalf("source consumed while destination stalled: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("source=%q want %q", got, payload)
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

func TestWaitReadableAndWritableUnblocksWhenDestDrains(t *testing.T) {
	srcR, srcW := pipePair(t)
	dstR, dstW := pipePair(t)
	fillPipeForPollTest(t, dstW)
	if _, err := srcW.Write([]byte("go")); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- waitReadableAndWritable(ctx, fileFD(t, srcR), fileFD(t, dstW))
	}()
	time.Sleep(50 * time.Millisecond)
	buf := make([]byte, 64<<10)
	if _, err := dstR.Read(buf); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("did not become ready after destination drained")
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(srcR, got); err != nil {
		t.Fatalf("source consumed before wait returned: %v", err)
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

func TestWaitReadableAndWritableSourceHangupWithDataBlockedDest(t *testing.T) {
	srcR, srcW := pipePair(t)
	dstR, dstW := pipePair(t)
	fillPipeForPollTest(t, dstW)
	if _, err := srcW.Write([]byte("go")); err != nil {
		t.Fatal(err)
	}
	if err := srcW.Close(); err != nil {
		t.Fatal(err)
	}

	n := countingPollWait(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- waitReadableAndWritable(ctx, fileFD(t, srcR), fileFD(t, dstW))
	}()
	time.Sleep(50 * time.Millisecond)
	if polls := n.Load(); polls > maxOneSidedPolls {
		cancel()
		t.Fatalf("polls=%d want <= %d while dest blocked with source hangup", polls, maxOneSidedPolls)
	}
	buf := make([]byte, 64<<10)
	if _, err := dstR.Read(buf); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("did not become ready after destination drained")
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(srcR, got); err != nil {
		t.Fatalf("source consumed before wait returned: %v", err)
	}
}

func TestWaitReadableAndWritableDestHangup(t *testing.T) {
	srcR, srcW := pipePair(t)
	dstR, dstW := pipePair(t)
	if _, err := srcW.Write([]byte("xy")); err != nil {
		t.Fatal(err)
	}
	if err := dstR.Close(); err != nil {
		t.Fatal(err)
	}

	n, err := waitPollWithTimeout(t, fileFD(t, srcR), fileFD(t, dstW), time.Second)
	// Linux pipes often report POLLOUT|POLLHUP together; that remains writable
	// until write, matching the previous poll contract. Hangup without POLLOUT
	// is a closed destination.
	if err != nil && err != io.ErrClosedPipe {
		t.Fatalf("dest hangup err=%v", err)
	}
	if n > maxOneSidedPolls {
		t.Fatalf("polls=%d want <= %d (busy-spin)", n, maxOneSidedPolls)
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(srcR, got); err != nil {
		t.Fatalf("source consumed after dest hangup: %v", err)
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

func TestWaitReadableAndWritableDestNval(t *testing.T) {
	srcR, srcW := pipePair(t)
	dstR, dstW := pipePair(t)
	nval, err := unix.Dup(int(dstW.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	owned := newOwnedFD(t, nval)
	if err := dstR.Close(); err != nil {
		t.Fatal(err)
	}
	if err := dstW.Close(); err != nil {
		t.Fatal(err)
	}
	owned.closeNow(t)
	if _, err := srcW.Write([]byte("xy")); err != nil {
		t.Fatal(err)
	}

	n, err := waitPollWithTimeout(t, fileFD(t, srcR), nval, time.Second)
	if err != io.ErrClosedPipe {
		t.Fatalf("nval dest err=%v want closed pipe", err)
	}
	if n > maxOneSidedPolls {
		t.Fatalf("polls=%d want <= %d (busy-spin)", n, maxOneSidedPolls)
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(srcR, got); err != nil {
		t.Fatalf("source consumed after dest nval: %v", err)
	}
}

func TestWaitReadableAndWritableInvalidFD(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitReadableAndWritable(ctx, -1, -1); err != unix.EBADF {
		t.Fatalf("err=%v want EBADF", err)
	}
}

func TestTransferPollClosedDestinationIsClean(t *testing.T) {
	srcR, srcW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srcR.Close() }()
	defer func() { _ = srcW.Close() }()

	dstR, dstW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	nval, err := unix.Dup(int(dstW.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = dstR.Close()
	_ = dstW.Close()
	if err := unix.Close(nval); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = Transfer(ctx,
		FDStream{R: srcR, W: io.Discard, C: nopCloser{}},
		FDStream{R: eofReader{}, W: nvalDest(nval), C: nopCloser{}},
		Config{BufferSize: 32, LeftToRight: true, Linger: 50 * time.Millisecond},
	)
	if err != nil {
		t.Fatalf("closed destination must be a clean EOF, got %v", err)
	}
}

// TestWaitReadableAndWritableStaleWaitingHangupRearms injects a waiting-poll
// POLLHUP that the 0-timeout confirmation poll does not observe. Omission
// must follow confirmed state so a later write re-arms source.
func TestWaitReadableAndWritableStaleWaitingHangupRearms(t *testing.T) {
	srcR, srcW := pipePair(t)
	_, dstW := pipePair(t)
	srcFD := fileFD(t, srcR)
	dstFD := fileFD(t, dstW)

	var injected atomic.Bool
	rearmed := make(chan struct{})
	var rearmOnce sync.Once

	hook := func(fds []unix.PollFd, timeoutMs int) (int, error) {
		if injected.Load() {
			for _, fd := range fds {
				if fd.Fd == int32(srcFD) && fd.Events&pollIn != 0 {
					rearmOnce.Do(func() { close(rearmed) })
				}
			}
			return poll(fds, timeoutMs)
		}
		n := 0
		for i := range fds {
			if fds[i].Fd == int32(srcFD) && fds[i].Events&pollIn != 0 {
				fds[i].Revents = pollHup
				n++
			}
		}
		if n == 0 {
			return poll(fds, timeoutMs)
		}
		injected.Store(true)
		return n, nil
	}
	done := startHookedWait(t, srcFD, dstFD, hook, 2*time.Second)

	select {
	case <-rearmed:
	case err := <-done:
		t.Fatalf("wait returned before stale hangup re-armed source: %v", err)
	case <-time.After(time.Second):
		t.Fatal("source stayed omitted after stale waiting POLLHUP")
	}

	if _, err := srcW.Write([]byte("go")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("after stale waiting hangup: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("wait did not return after source re-arm write")
	}

	got := make([]byte, 2)
	if _, err := io.ReadFull(srcR, got); err != nil {
		t.Fatalf("source consumed or unread: %v", err)
	}
	if string(got) != "go" {
		t.Fatalf("source=%q want go", got)
	}
}

// TestWaitReadableAndWritableMaskedDestCloseDarwinModel closes the destination
// after it has been masked (Events=0). The waiting poll hides Events=0 the
// way Darwin does, so timeout confirmation must observe the closed fd.
func TestWaitReadableAndWritableMaskedDestCloseDarwinModel(t *testing.T) {
	runMaskedDestCloseAfterReady(t, darwinZeroEventPollWait)
}
