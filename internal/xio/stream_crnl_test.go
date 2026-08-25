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
