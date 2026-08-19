package relay

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestTransferPropagatesRawDumpErrors(t *testing.T) {
	want := errors.New("dump failed")
	left := FDStream{R: &oneShotReader{data: []byte("payload")}, W: io.Discard, C: nopCloser{}}
	right := FDStream{R: eofReader{}, W: io.Discard, C: nopCloser{}}
	err := Transfer(context.Background(), left, right, Config{
		LeftToRight: true,
		RawLeft:     errorWriter{err: want},
	})
	if !errors.Is(err, want) {
		t.Fatalf("Transfer error = %v, want wrapped %v", err, want)
	}
}

func TestTransferRejectsShortRawDumpWrites(t *testing.T) {
	left := FDStream{R: &oneShotReader{data: []byte("payload")}, W: io.Discard, C: nopCloser{}}
	right := FDStream{R: eofReader{}, W: io.Discard, C: nopCloser{}}
	err := Transfer(context.Background(), left, right, Config{
		LeftToRight: true,
		RawLeft:     shortWriter{},
	})
	if !errors.Is(err, io.ErrShortWrite) || !strings.Contains(err.Error(), "raw left dump") {
		t.Fatalf("Transfer error = %v, want raw dump short write", err)
	}
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
