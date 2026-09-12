package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestSelectTransferErrorRules(t *testing.T) {
	boom := errors.New("boom")
	later := errors.New("later")
	wrappedCanceled := fmt.Errorf("wrap: %w", context.Canceled)

	first := selectTransferError(nil, dirOutcome{dir: dirLeftToRight, err: boom})
	if !errors.Is(first, boom) || !strings.HasPrefix(first.Error(), ">: ") {
		t.Fatalf("first left→right error = %v", first)
	}

	kept := selectTransferError(first, dirOutcome{dir: dirRightToLeft, err: later})
	if kept != first {
		t.Fatalf("later error replaced first: %v", kept)
	}

	if err := selectTransferError(nil, dirOutcome{dir: dirLeftToRight}); err != nil {
		t.Fatalf("nil outcome selected: %v", err)
	}
	if err := selectTransferError(nil, dirOutcome{dir: dirLeftToRight, err: context.Canceled}); err != nil {
		t.Fatalf("exact Canceled selected: %v", err)
	}

	got := selectTransferError(nil, dirOutcome{dir: dirRightToLeft, err: wrappedCanceled})
	if !errors.Is(got, context.Canceled) || !strings.HasPrefix(got.Error(), "<: ") {
		t.Fatalf("wrapped Canceled not selected: %v", got)
	}

	deadline := selectTransferError(nil, dirOutcome{dir: dirLeftToRight, err: context.DeadlineExceeded})
	if !errors.Is(deadline, context.DeadlineExceeded) {
		t.Fatalf("DeadlineExceeded not selected: %v", deadline)
	}
}

func TestTransferOutcomesDrainIsNotSelected(t *testing.T) {
	var o transferOutcomes
	o.record(dirOutcome{dir: dirLeftToRight}, true)
	o.record(dirOutcome{dir: dirRightToLeft, err: errors.New("late")}, false)
	if err := o.selectedError(); err != nil {
		t.Fatalf("drained error selected: %v", err)
	}
	if o.rightToLeft.err == nil {
		t.Fatal("drained outcome was not stored")
	}
}

func TestTransferCleanEOFIsNil(t *testing.T) {
	left := FDStream{R: eofReader{}, W: io.Discard, C: nopCloser{}}
	right := FDStream{R: eofReader{}, W: io.Discard, C: nopCloser{}}
	if err := Transfer(context.Background(), left, right, Config{}); err != nil {
		t.Fatalf("clean EOF: %v", err)
	}
}

func TestTransferIgnoresExactCanceled(t *testing.T) {
	want := errors.New("boom")
	left := FDStream{R: errorReader{err: context.Canceled}, W: io.Discard, C: nopCloser{}}
	right := FDStream{R: errorReader{err: want}, W: io.Discard, C: nopCloser{}}
	err := Transfer(context.Background(), left, right, Config{})
	if !errors.Is(err, want) {
		t.Fatalf("Transfer error = %v, want %v", err, want)
	}
}

func TestTransferSelectsWrappedCanceled(t *testing.T) {
	wrapped := fmt.Errorf("wrap: %w", context.Canceled)
	left := FDStream{R: errorReader{err: wrapped}, W: io.Discard, C: nopCloser{}}
	right := FDStream{R: eofReader{}, W: io.Discard, C: nopCloser{}}
	err := Transfer(context.Background(), left, right, Config{LeftToRight: true})
	if !errors.Is(err, context.Canceled) || !strings.HasPrefix(err.Error(), ">: ") {
		t.Fatalf("wrapped Canceled = %v", err)
	}
}

func TestTransferBenignCloseIsNil(t *testing.T) {
	left := FDStream{R: strings.NewReader("payload"), W: io.Discard, C: nopCloser{}}
	right := FDStream{R: eofReader{}, W: closedPipeWriter{}, C: nopCloser{}}
	if err := Transfer(context.Background(), left, right, Config{LeftToRight: true}); err != nil {
		t.Fatalf("benign close: %v", err)
	}
}

func TestOnEOFStillReportsPollSrcFD(t *testing.T) {
	var fds []int
	left := FDStream{R: eofReader{}, W: io.Discard, C: nopCloser{}}
	right := FDStream{R: eofReader{}, W: io.Discard, C: nopCloser{}}
	if err := Transfer(context.Background(), left, right, Config{
		LeftToRight: true,
		OnEOF:       func(_, fd int) { fds = append(fds, fd) },
	}); err != nil {
		t.Fatal(err)
	}
	// Structural change only: unknown source FDs stay -1 here. Mapping
	// unknown → 0 is a separate reporting fix.
	if len(fds) != 1 || fds[0] != -1 {
		t.Fatalf("OnEOF fds=%v, want [-1]", fds)
	}
}

func TestTransferLingerZeroDoesNotInventError(t *testing.T) {
	hold := &holdCloser{closed: make(chan struct{})}
	left := FDStream{R: eofReader{}, W: io.Discard, C: nopCloser{}}
	right := FDStream{R: hold, W: io.Discard, C: hold}
	if err := Transfer(context.Background(), left, right, Config{Linger: 0}); err != nil {
		t.Fatalf("linger 0 invented error: %v", err)
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

type closedPipeWriter struct{}

func (closedPipeWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

type holdCloser struct {
	once   sync.Once
	closed chan struct{}
}

func (h *holdCloser) Read([]byte) (int, error) {
	<-h.closed
	return 0, io.EOF
}

func (h *holdCloser) Write(p []byte) (int, error) { return len(p), nil }

func (h *holdCloser) Close() error {
	h.once.Do(func() { close(h.closed) })
	return nil
}
