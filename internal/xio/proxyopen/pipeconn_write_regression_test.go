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

var errTransportWrite = errors.New("transport write failed")

const reviewPayload = "seven!!" // 7 bytes, same as the native review reproducer

type scriptedWriteCloser struct {
	n   int
	err error
	mu  sync.Mutex
	got []byte
}

func (s *scriptedWriteCloser) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.n
	if n > len(p) {
		n = len(p)
	}
	if n > 0 {
		s.got = append(s.got, p[:n]...)
	}
	return n, s.err
}

func (s *scriptedWriteCloser) Close() error { return nil }

type enterWriteCloser struct {
	w       io.WriteCloser
	entered chan struct{}
	once    sync.Once
}

func (e *enterWriteCloser) Write(p []byte) (int, error) {
	e.once.Do(func() { close(e.entered) })
	return e.w.Write(p)
}

func (e *enterWriteCloser) Close() error { return e.w.Close() }

func TestReviewPipeConnWriteZeroProgressError(t *testing.T) {
	w := &scriptedWriteCloser{n: 0, err: errTransportWrite}
	c := newPipeConn(io.NopCloser(bytes.NewReader(nil)), w, staticAddr("h2", "l"), staticAddr("h2", "r"), nil)
	t.Cleanup(func() { _ = c.Close() })
	n, err := c.Write([]byte(reviewPayload))
	if n != 0 || !errors.Is(err, errTransportWrite) {
		t.Fatalf("Write n=%d err=%v want 0, %v", n, err, errTransportWrite)
	}
	if len(w.got) != 0 {
		t.Fatalf("transport got %q", w.got)
	}
}

func TestReviewPipeConnWritePartialProgressError(t *testing.T) {
	w := &scriptedWriteCloser{n: 3, err: errTransportWrite}
	c := newPipeConn(io.NopCloser(bytes.NewReader(nil)), w, staticAddr("h2", "l"), staticAddr("h2", "r"), nil)
	t.Cleanup(func() { _ = c.Close() })
	n, err := c.Write([]byte(reviewPayload))
	if n != 3 || !errors.Is(err, errTransportWrite) {
		t.Fatalf("Write n=%d err=%v want 3, %v", n, err, errTransportWrite)
	}
	if string(w.got) != reviewPayload[:3] {
		t.Fatalf("transport got %q want %q", w.got, reviewPayload[:3])
	}
}

func TestReviewPipeConnWriteDeadlineThenCloseWriteDropsUnsent(t *testing.T) {
	pr, pw := io.Pipe()
	entered := make(chan struct{})
	c := newPipeConn(pr, &enterWriteCloser{w: pw, entered: entered}, staticAddr("h2", "l"), staticAddr("h2", "r"), nil)
	t.Cleanup(func() { _ = c.Close(); _ = pr.Close() })

	done := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := c.Write([]byte(reviewPayload))
		done <- struct {
			n   int
			err error
		}{n, err}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("underlying Write did not start")
	}
	if err := c.SetWriteDeadline(time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var got struct {
		n   int
		err error
	}
	select {
	case got = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Write ignored deadline after underlying Write started")
	}
	if got.n != 0 || !errors.Is(got.err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write n=%d err=%v want 0, deadline exceeded", got.n, got.err)
	}

	peer := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(pr)
		peer <- b
	}()
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got := <-peer; len(got) != 0 {
		t.Fatalf("peer got %q after CloseWrite; Write reported n=0 so nothing was delivered", got)
	}
}

func TestReviewPipeConnWriteDeadlineRetryNoDuplicate(t *testing.T) {
	pr, pw := io.Pipe()
	entered := make(chan struct{})
	c := newPipeConn(pr, &enterWriteCloser{w: pw, entered: entered}, staticAddr("h2", "l"), staticAddr("h2", "r"), nil)
	t.Cleanup(func() { _ = c.Close(); _ = pr.Close() })

	done := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := c.Write([]byte(reviewPayload))
		done <- struct {
			n   int
			err error
		}{n, err}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("underlying Write did not start")
	}
	if err := c.SetWriteDeadline(time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.n != 0 || !errors.Is(got.err, os.ErrDeadlineExceeded) {
			t.Fatalf("first Write n=%d err=%v want 0, deadline exceeded", got.n, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Write ignored deadline")
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
	got := <-readDone
	if string(got) != reviewPayload {
		t.Fatalf("peer got %q want one copy of %q", got, reviewPayload)
	}
}

func TestReviewPipeConnWriteDeadlineExtendThenDeliver(t *testing.T) {
	pr, pw := io.Pipe()
	entered := make(chan struct{})
	c := newPipeConn(pr, &enterWriteCloser{w: pw, entered: entered}, staticAddr("h2", "l"), staticAddr("h2", "r"), nil)
	t.Cleanup(func() { _ = c.Close(); _ = pr.Close() })

	done := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := c.Write([]byte(reviewPayload))
		done <- struct {
			n   int
			err error
		}{n, err}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("underlying Write did not start")
	}
	if err := c.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(pr, make([]byte, len(reviewPayload)))
		readDone <- err
	}()
	select {
	case got := <-done:
		if got.n != len(reviewPayload) || got.err != nil {
			t.Fatalf("extended Write n=%d err=%v", got.n, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("extended Write did not finish")
	}
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
}

func TestReviewPipeConnCloseWritePendingMatchesCount(t *testing.T) {
	pr, pw := io.Pipe()
	entered := make(chan struct{})
	c := newPipeConn(pr, &enterWriteCloser{w: pw, entered: entered}, staticAddr("h2", "l"), staticAddr("h2", "r"), nil)
	t.Cleanup(func() { _ = c.Close(); _ = pr.Close() })

	done := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := c.Write([]byte(reviewPayload))
		done <- struct {
			n   int
			err error
		}{n, err}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("underlying Write did not start")
	}
	peer := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(pr)
		peer <- b
	}()
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var got struct {
		n   int
		err error
	}
	select {
	case got = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Write did not return after CloseWrite")
	}
	delivered := <-peer
	if got.n != len(delivered) {
		t.Fatalf("Write n=%d peer=%q; count must match delivered bytes", got.n, delivered)
	}
}
