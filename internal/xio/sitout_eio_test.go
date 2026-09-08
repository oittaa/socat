//go:build linux || darwin

package xio

import (
	"errors"
	"io"
	"syscall"
	"testing"
	"time"
)

type seqReader struct {
	err  error
	n    int
	from int
	ok   []byte
}

func (s *seqReader) Read(p []byte) (int, error) {
	if s.from < s.n {
		s.from++
		return 0, s.err
	}
	n := copy(p, s.ok)
	return n, nil
}

func TestSitoutEIOZeroDurationIsEOF(t *testing.T) {
	r := wrapSitoutEIORead(&seqReader{err: syscall.EIO, n: 1, ok: []byte("x")}, 0)
	n, err := r.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("n=%d err=%v want EOF", n, err)
	}
}

func TestSitoutEIORecoversWithinTimeout(t *testing.T) {
	r := wrapSitoutEIORead(&seqReader{err: syscall.EIO, n: 1, ok: []byte("ok")}, 50*time.Millisecond)
	buf := make([]byte, 8)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ok" {
		t.Fatalf("got %q", buf[:n])
	}
}

func TestSitoutEIOTimeoutReturnsEIO(t *testing.T) {
	r := wrapSitoutEIORead(&seqReader{err: syscall.EIO, n: 100, ok: []byte("x")}, 20*time.Millisecond)
	n, err := r.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, syscall.EIO) {
		t.Fatalf("n=%d err=%v want EIO", n, err)
	}
}

func TestSitoutEIOTicksMatchesClassic(t *testing.T) {
	if got := sitoutEIOTicks(0); got != 0 {
		t.Fatalf("ticks(0)=%d", got)
	}
	if got := sitoutEIOTicks(time.Second); got != 100 {
		t.Fatalf("ticks(1s)=%d want 100", got)
	}
	if got := sitoutEIOTicks(1500 * time.Millisecond); got != 150 {
		t.Fatalf("ticks(1.5s)=%d want 150", got)
	}
	if got := sitoutEIOTicks(time.Microsecond); got != 1 {
		t.Fatalf("ticks(1us)=%d want 1", got)
	}
}
