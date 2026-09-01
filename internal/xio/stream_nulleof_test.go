package xio

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type zeroNilReader struct{}

func (zeroNilReader) Read([]byte) (int, error) { return 0, nil }

func TestNullEOFReaderEmptyBufferIsNotEOF(t *testing.T) {
	t.Parallel()
	r := &nullEOFReader{r: bytes.NewReader([]byte("ab"))}
	n, err := r.Read(nil)
	if n != 0 || err != nil {
		t.Fatalf("empty dest n=%d err=%v want 0, nil", n, err)
	}
	buf := make([]byte, 2)
	n, err = r.Read(buf)
	if err != nil || string(buf[:n]) != "ab" {
		t.Fatalf("payload n=%d err=%v data=%q", n, err, buf[:n])
	}
}

func TestNullEOFReaderZeroLengthReadIsEOF(t *testing.T) {
	t.Parallel()
	r := &nullEOFReader{r: zeroNilReader{}}
	n, err := r.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("n=%d err=%v want EOF", n, err)
	}
}
