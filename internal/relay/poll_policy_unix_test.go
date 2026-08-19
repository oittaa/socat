//go:build unix

package relay

import (
	"context"
	"io"
	"os"
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
