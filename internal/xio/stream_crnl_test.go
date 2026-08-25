package xio

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type oneByteThenErr struct {
	wrote int
	err   error
	buf   bytes.Buffer
}

type scriptedWrite struct {
	results []struct {
		n   int
		err error
	}
	buf bytes.Buffer
}

func (w *scriptedWrite) Write(p []byte) (int, error) {
	if len(w.results) == 0 {
		return w.buf.Write(p)
	}
	r := w.results[0]
	w.results = w.results[1:]
	if r.n > len(p) {
		r.n = len(p)
	}
	_, _ = w.buf.Write(p[:r.n])
	return r.n, r.err
}

func (w *oneByteThenErr) Write(p []byte) (int, error) {
	if w.wrote == 0 && len(p) > 0 {
		n, _ := w.buf.Write(p[:1])
		w.wrote++
		return n, w.err
	}
	n, err := w.buf.Write(p)
	w.wrote += n
	return n, err
}

func TestCrnlWriterPartialCRLFDoesNotDoubleCR(t *testing.T) {
	w := &oneByteThenErr{err: io.ErrShortWrite}
	c := &crnlWriter{w: w}
	n, err := c.Write([]byte("\n"))
	if n != 0 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("first write n=%d err=%v", n, err)
	}
	if !c.pendingLF {
		t.Fatal("expected pending LF after writing only CR")
	}
	n, err = c.Write([]byte("\n"))
	if err != nil || n != 1 {
		t.Fatalf("retry n=%d err=%v", n, err)
	}
	if got := w.buf.String(); got != "\r\n" {
		t.Fatalf("got %q want CRLF", got)
	}
}

func TestCrnlWriterCountsCompletedCRLFWithError(t *testing.T) {
	wantErr := errors.New("completed with error")
	w := &scriptedWrite{results: []struct {
		n   int
		err error
	}{{n: 2, err: wantErr}}}
	c := &crnlWriter{w: w}
	n, err := c.Write([]byte("\n"))
	if n != 1 || !errors.Is(err, wantErr) {
		t.Fatalf("write n=%d err=%v", n, err)
	}
	if got := w.buf.String(); got != "\r\n" {
		t.Fatalf("got %q want CRLF", got)
	}
}

func TestCrnlWriterCountsPendingLFCompletedWithError(t *testing.T) {
	wantErr := errors.New("completed with error")
	w := &scriptedWrite{results: []struct {
		n   int
		err error
	}{{n: 1, err: io.ErrShortWrite}, {n: 1, err: wantErr}}}
	c := &crnlWriter{w: w}
	n, err := c.Write([]byte("\n"))
	if n != 0 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("first write n=%d err=%v", n, err)
	}
	n, err = c.Write([]byte("\n"))
	if n != 1 || !errors.Is(err, wantErr) {
		t.Fatalf("retry n=%d err=%v", n, err)
	}
	if c.pendingLF {
		t.Fatal("pending LF was not cleared")
	}
	if got := w.buf.String(); got != "\r\n" {
		t.Fatalf("got %q want CRLF", got)
	}
}
