//go:build unix

package xio

import (
	"errors"
	"io"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
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

func TestSitoutEIOParse(t *testing.T) {
	s, err := parse.ParseSpec("PTY")
	if err != nil {
		t.Fatal(err)
	}
	d, err := SitoutEIO(s)
	if err != nil || d != 0 {
		t.Fatalf("omitted: d=%v err=%v", d, err)
	}
	s, err = parse.ParseSpec("PTY,sitout-eio=0")
	if err != nil {
		t.Fatal(err)
	}
	d, err = SitoutEIO(s)
	if err != nil || d != 0 {
		t.Fatalf("=0: d=%v err=%v", d, err)
	}
	s, err = parse.ParseSpec("PTY,sitout-eio=1.5")
	if err != nil {
		t.Fatal(err)
	}
	d, err = SitoutEIO(s)
	if err != nil || d != 1500*time.Millisecond {
		t.Fatalf("=1.5: d=%v err=%v", d, err)
	}
	s, err = parse.ParseSpec("PTY,sitout-eio")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SitoutEIO(s); err == nil {
		t.Fatal("bare sitout-eio must require a value")
	}
}
