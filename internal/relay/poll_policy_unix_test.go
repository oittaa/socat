//go:build linux || darwin

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

func TestWaitReadableAndWritableIdleSourceTimesOut(t *testing.T) {
	srcR, _ := pipePair(t)
	_, dstW := pipePair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err := waitReadableAndWritable(ctx, fileFD(t, srcR), fileFD(t, dstW))
	if err == nil {
		t.Fatal("idle source returned as ready")
	}
	if err != context.DeadlineExceeded {
		t.Fatalf("err=%v want deadline exceeded", err)
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitReadableAndWritable(ctx, fileFD(t, srcR), fileFD(t, dstW)); err != nil {
		t.Fatalf("source hangup: %v", err)
	}
}

func TestWaitReadableAndWritableIdleSourceDestHangup(t *testing.T) {
	srcR, _ := pipePair(t)
	dstR, dstW := pipePair(t)
	if err := dstR.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err := waitReadableAndWritable(ctx, fileFD(t, srcR), fileFD(t, dstW))
	if err != nil && err != io.ErrClosedPipe && err != context.DeadlineExceeded {
		t.Fatalf("err=%v", err)
	}
}

func TestWaitReadableAndWritableInvalidFD(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitReadableAndWritable(ctx, -1, -1); err != unix.EBADF {
		t.Fatalf("err=%v want EBADF", err)
	}
}

func TestWaitReadableAndWritableClosedDestination(t *testing.T) {
	srcR, _ := pipePair(t)
	_, dstW := pipePair(t)
	fd := fileFD(t, dstW)
	if err := dstW.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitReadableAndWritable(ctx, fileFD(t, srcR), fd); err != io.ErrClosedPipe {
		t.Fatalf("closed destination: %v", err)
	}
}
