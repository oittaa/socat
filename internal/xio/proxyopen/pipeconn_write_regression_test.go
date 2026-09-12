package proxyopen

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"
)

const (
	reviewPayload = "seven!!" // 7 bytes, same as the native review reproducer
	reviewOld     = "OLDDATA!"
	reviewNew     = "NEWDATA!"
)

type writeResult struct {
	n   int
	err error
}

func reviewWriteConn(t *testing.T, bufMax int) (*pipeConn, *reqPipeReader) {
	t.Helper()
	pr, pw := newReqPipe(bufMax)
	c := newPipeConn(io.NopCloser(bytes.NewReader(nil)), pw, staticAddr("h2", "l"), staticAddr("h2", "r"), nil)
	t.Cleanup(func() {
		pipeConnWaitHook = nil
		_ = c.Close()
		_ = pr.Close()
	})
	return c, pr
}

func waitPipe(t *testing.T) <-chan struct{} {
	t.Helper()
	entered := make(chan struct{})
	var once sync.Once
	pipeConnWaitHook = func() { once.Do(func() { close(entered) }) }
	t.Cleanup(func() { pipeConnWaitHook = nil })
	return entered
}

func startWrite(c *pipeConn, p string) <-chan writeResult {
	done := make(chan writeResult, 1)
	go func() {
		n, err := c.Write([]byte(p))
		done <- writeResult{n, err}
	}()
	return done
}

func waitEnter(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("Write did not block")
	}
}

func waitResult(t *testing.T, done <-chan writeResult) writeResult {
	t.Helper()
	select {
	case got := <-done:
		return got
	case <-time.After(2 * time.Second):
		t.Fatal("Write did not return")
		return writeResult{}
	}
}

func TestReviewPipeConnTimeoutThenDifferentPayload(t *testing.T) {
	c, pr := reviewWriteConn(t, 0)
	entered := waitPipe(t)
	done := startWrite(c, reviewOld)
	waitEnter(t, entered)
	if err := c.SetWriteDeadline(time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	got := waitResult(t, done)
	if got.n != 0 || !errors.Is(got.err, os.ErrDeadlineExceeded) {
		t.Fatalf("OLD Write n=%d err=%v want 0, deadline exceeded", got.n, got.err)
	}
	if err := c.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	readDone := make(chan []byte, 1)
	go func() {
		buf := make([]byte, len(reviewOld)+len(reviewNew))
		n, _ := pr.Read(buf)
		readDone <- append([]byte(nil), buf[:n]...)
	}()
	n, err := c.Write([]byte(reviewNew))
	if err != nil {
		t.Fatalf("NEW Write n=%d err=%v", n, err)
	}
	select {
	case peer := <-readDone:
		if n != len(reviewNew) || string(peer) != reviewNew {
			t.Fatalf("NEW Write n=%d peer=%q; want n=%d peer=%q", n, peer, len(reviewNew), reviewNew)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer did not receive NEW")
	}
}

func TestReviewPipeConnSamePayloadRetryAfterZero(t *testing.T) {
	c, pr := reviewWriteConn(t, 0)
	entered := waitPipe(t)
	done := startWrite(c, reviewPayload)
	waitEnter(t, entered)
	if err := c.SetWriteDeadline(time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	got := waitResult(t, done)
	if got.n != 0 || !errors.Is(got.err, os.ErrDeadlineExceeded) {
		t.Fatalf("first Write n=%d err=%v want 0, deadline exceeded", got.n, got.err)
	}
	if err := c.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	readDone := make(chan []byte, 1)
	go func() {
		buf := make([]byte, len(reviewPayload)*2)
		n, _ := pr.Read(buf)
		readDone <- append([]byte(nil), buf[:n]...)
	}()
	n, err := c.Write([]byte(reviewPayload))
	if err != nil || n != len(reviewPayload) {
		t.Fatalf("retry Write n=%d err=%v want %d", n, err, len(reviewPayload))
	}
	peer := <-readDone
	if string(peer) != reviewPayload {
		t.Fatalf("peer got %q want one copy of %q", peer, reviewPayload)
	}
}

func TestReviewPipeConnSuffixRetryAfterPartial(t *testing.T) {
	c, pr := reviewWriteConn(t, 4)
	entered := waitPipe(t)
	done := startWrite(c, reviewPayload)
	waitEnter(t, entered)
	if err := c.SetWriteDeadline(time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	got := waitResult(t, done)
	if got.n != 4 || !errors.Is(got.err, os.ErrDeadlineExceeded) {
		t.Fatalf("first Write n=%d err=%v want 4, deadline exceeded", got.n, got.err)
	}
	if err := c.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	peerCh := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(pr)
		peerCh <- b
	}()
	n, err := c.Write([]byte(reviewPayload[got.n:]))
	if err != nil || n != len(reviewPayload)-got.n {
		t.Fatalf("suffix Write n=%d err=%v", n, err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	peer := <-peerCh
	if string(peer) != reviewPayload {
		t.Fatalf("peer got %q want %q (n1=%d n2=%d)", peer, reviewPayload, got.n, n)
	}
}

func TestReviewPipeConnConcurrentTimeoutNoCrossAck(t *testing.T) {
	c, pr := reviewWriteConn(t, 0)
	waits := make(chan struct{}, 8)
	pipeConnWaitHook = func() {
		select {
		case waits <- struct{}{}:
		default:
		}
	}
	t.Cleanup(func() { pipeConnWaitHook = nil })

	oldDone := startWrite(c, reviewOld)
	waitEnter(t, waits)
	newDone := startWrite(c, reviewNew)
	waitEnter(t, waits)
	if err := c.SetWriteDeadline(time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	old := waitResult(t, oldDone)
	if old.n != 0 || !errors.Is(old.err, os.ErrDeadlineExceeded) {
		t.Fatalf("OLD Write n=%d err=%v want 0, deadline exceeded", old.n, old.err)
	}
	if err := c.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	var neu writeResult
	select {
	case neu = <-newDone:
		if neu.n != 0 {
			t.Fatalf("NEW acked %d of another call after the shared deadline", neu.n)
		}
		readDone := make(chan []byte, 1)
		go func() {
			buf := make([]byte, 8)
			n, err := io.ReadFull(pr, buf)
			if err != nil {
				readDone <- nil
				return
			}
			readDone <- buf[:n]
		}()
		n, err := c.Write([]byte("AFTER!!!"))
		if err != nil || n != 8 {
			t.Fatalf("after-timeout Write n=%d err=%v", n, err)
		}
		select {
		case peer := <-readDone:
			if string(peer) != "AFTER!!!" {
				t.Fatalf("peer got %q after concurrent timeout; tunnel should still accept a new Write", peer)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("peer did not receive the post-timeout Write")
		}
	case <-waits:
		readDone := make(chan []byte, 1)
		go func() {
			buf := make([]byte, len(reviewNew))
			n, _ := io.ReadFull(pr, buf)
			readDone <- buf[:n]
		}()
		neu = waitResult(t, newDone)
		peer := <-readDone
		if neu.n != len(reviewNew) || string(peer) != reviewNew {
			t.Fatalf("NEW n=%d peer=%q; must be this call’s payload, not OLD", neu.n, peer)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("NEW Write neither returned nor blocked for a reader")
	}
}

func TestReviewPipeConnWriteZeroProgressError(t *testing.T) {
	c, pr := reviewWriteConn(t, 0)
	if err := pr.Close(); err != nil {
		t.Fatal(err)
	}
	n, err := c.Write([]byte(reviewPayload))
	if n != 0 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Write n=%d err=%v want 0, %v", n, err, io.ErrClosedPipe)
	}
}

func TestReviewPipeConnWritePartialProgressError(t *testing.T) {
	c, pr := reviewWriteConn(t, 0)
	entered := waitPipe(t)
	done := startWrite(c, reviewPayload)
	waitEnter(t, entered)
	buf := make([]byte, 3)
	n, err := pr.Read(buf)
	if err != nil || n != 3 {
		t.Fatalf("peer Read n=%d err=%v", n, err)
	}
	if err := pr.Close(); err != nil {
		t.Fatal(err)
	}
	got := waitResult(t, done)
	if got.n != 3 || !errors.Is(got.err, io.ErrClosedPipe) {
		t.Fatalf("Write n=%d err=%v want 3, %v", got.n, got.err, io.ErrClosedPipe)
	}
	if string(buf) != reviewPayload[:3] {
		t.Fatalf("peer got %q want %q", buf, reviewPayload[:3])
	}
}

func TestReviewPipeConnLargeWrite(t *testing.T) {
	payload := bytes.Repeat([]byte("L"), pipeConnBuffer+8192)
	c, pr := reviewWriteConn(t, pipeConnBuffer)
	peerCh := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(pr)
		peerCh <- b
	}()
	n, err := c.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("Write n=%d err=%v want %d", n, err, len(payload))
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got := <-peerCh; !bytes.Equal(got, payload) {
		t.Fatalf("peer len=%d want %d", len(got), len(payload))
	}
}

func TestReviewPipeConnWriteDeadlineExtendThenDeliver(t *testing.T) {
	c, pr := reviewWriteConn(t, 0)
	entered := waitPipe(t)
	done := startWrite(c, reviewPayload)
	waitEnter(t, entered)
	if err := c.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(pr, make([]byte, len(reviewPayload)))
		readDone <- err
	}()
	got := waitResult(t, done)
	if got.n != len(reviewPayload) || got.err != nil {
		t.Fatalf("extended Write n=%d err=%v", got.n, got.err)
	}
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
}

func TestReviewPipeConnCloseWritePendingMatchesCount(t *testing.T) {
	c, pr := reviewWriteConn(t, 0)
	entered := waitPipe(t)
	done := startWrite(c, reviewPayload)
	waitEnter(t, entered)
	peer := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(pr)
		peer <- b
	}()
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got := waitResult(t, done)
	delivered := <-peer
	if got.n != len(delivered) {
		t.Fatalf("Write n=%d peer=%q; count must match delivered bytes", got.n, delivered)
	}
	if got.n > 0 && string(delivered) != reviewPayload[:got.n] {
		t.Fatalf("peer %q is not this Write’s prefix (n=%d)", delivered, got.n)
	}
}
