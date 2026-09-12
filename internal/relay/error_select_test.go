package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestClassifyDirError(t *testing.T) {
	if got := classifyDirError(dirLeftToRight, context.Canceled); got.class != classCanceled || got.err != context.Canceled {
		t.Fatalf("exact Canceled = %+v, want classCanceled", got)
	}
	wrapped := fmt.Errorf("wrap: %w", context.Canceled)
	if got := classifyDirError(dirRightToLeft, wrapped); got.class != classFailed || got.err != wrapped {
		t.Fatalf("wrapped Canceled = %+v, want classFailed", got)
	}
	if got := classifyDirError(dirLeftToRight, context.DeadlineExceeded); got.class != classFailed {
		t.Fatalf("DeadlineExceeded = %+v, want classFailed", got)
	}
}

func TestSourceEOFAndDestCloseAreDistinct(t *testing.T) {
	if dirEOF(dirLeftToRight).class == dirClosed(dirLeftToRight).class {
		t.Fatal("source EOF and dest close share a class")
	}
	if err := selectTransferError(nil, dirEOF(dirLeftToRight)); err != nil {
		t.Fatalf("source EOF selected: %v", err)
	}
	if err := selectTransferError(nil, dirClosed(dirRightToLeft)); err != nil {
		t.Fatalf("dest close selected: %v", err)
	}
}

func TestSelectTransferErrorRules(t *testing.T) {
	boom := errors.New("boom")
	later := errors.New("later")
	wrappedCanceled := fmt.Errorf("wrap: %w", context.Canceled)

	first := selectTransferError(nil, classifyDirError(dirLeftToRight, boom))
	if !errors.Is(first, boom) || !strings.HasPrefix(first.Error(), ">: ") {
		t.Fatalf("first left→right error = %v", first)
	}

	kept := selectTransferError(first, classifyDirError(dirRightToLeft, later))
	if kept != first {
		t.Fatalf("later error replaced first: %v", kept)
	}

	if err := selectTransferError(nil, dirEOF(dirLeftToRight)); err != nil {
		t.Fatalf("source EOF selected: %v", err)
	}
	if err := selectTransferError(nil, classifyDirError(dirLeftToRight, context.Canceled)); err != nil {
		t.Fatalf("exact Canceled selected: %v", err)
	}

	got := selectTransferError(nil, classifyDirError(dirRightToLeft, wrappedCanceled))
	if !errors.Is(got, context.Canceled) || !strings.HasPrefix(got.Error(), "<: ") {
		t.Fatalf("wrapped Canceled not selected: %v", got)
	}

	deadline := selectTransferError(nil, classifyDirError(dirLeftToRight, context.DeadlineExceeded))
	if !errors.Is(deadline, context.DeadlineExceeded) {
		t.Fatalf("DeadlineExceeded not selected: %v", deadline)
	}

	// Classification is authoritative. Selection does not re-inspect err.
	ignored := dirOutcome{dir: dirLeftToRight, class: classCanceled, err: boom}
	if err := selectTransferError(nil, ignored); err != nil {
		t.Fatalf("non-failed class selected: %v", err)
	}
}

func TestTransferOutcomesDrainIsNotSelected(t *testing.T) {
	var o transferOutcomes
	o.accept(dirEOF(dirLeftToRight), true)
	o.accept(classifyDirError(dirRightToLeft, errors.New("late")), false)
	if err := selectedTransferError(o); err != nil {
		t.Fatalf("drained error selected: %v", err)
	}
	if o.rightToLeft.err == nil || o.rightToLeft.class != classFailed {
		t.Fatal("drained outcome was not stored")
	}
	if len(o.inspect) != 1 || o.inspect[0] != dirLeftToRight {
		t.Fatalf("inspect = %v, want only left→right", o.inspect)
	}
}

func TestTransferOutcomesSelectsLiveOnly(t *testing.T) {
	boom := errors.New("boom")
	later := errors.New("later")

	var firstWins transferOutcomes
	firstWins.accept(classifyDirError(dirLeftToRight, boom), true)
	firstWins.accept(classifyDirError(dirRightToLeft, later), false)
	err := selectedTransferError(firstWins)
	if !errors.Is(err, boom) || !strings.HasPrefix(err.Error(), ">: ") {
		t.Fatalf("live boom = %v", err)
	}

	var canceledThenDrained transferOutcomes
	canceledThenDrained.accept(classifyDirError(dirLeftToRight, context.Canceled), true)
	canceledThenDrained.accept(classifyDirError(dirRightToLeft, boom), false)
	if err := selectedTransferError(canceledThenDrained); err != nil {
		t.Fatalf("live Canceled plus drained boom = %v", err)
	}
	if canceledThenDrained.rightToLeft.err != boom {
		t.Fatal("drained boom was not stored")
	}
}

func TestCopyDirReturnsSourceEOF(t *testing.T) {
	left := FDStream{R: eofReader{}, W: io.Discard, C: nopCloser{}}
	right := FDStream{R: eofReader{}, W: io.Discard, C: nopCloser{}}
	got := copyDir(context.Background(), dirTask{
		dir: dirLeftToRight, dst: right, src: left, dstFD: -1, srcFD: -1,
		bytes: new(atomic.Uint64), blocks: new(atomic.Uint64),
	}, Config{BufferSize: 32}, func() {})
	if got.dir != dirLeftToRight || got.class != classEOF {
		t.Fatalf("copyDir = %+v, want classEOF", got)
	}
}

func TestCopyDirReturnsDestClose(t *testing.T) {
	left := FDStream{R: strings.NewReader("payload"), W: io.Discard, C: nopCloser{}}
	right := FDStream{R: eofReader{}, W: closedPipeWriter{}, C: nopCloser{}}
	got := copyDir(context.Background(), dirTask{
		dir: dirLeftToRight, dst: right, src: left, dstFD: -1, srcFD: -1,
		bytes: new(atomic.Uint64), blocks: new(atomic.Uint64),
	}, Config{BufferSize: 32}, func() {})
	if got.dir != dirLeftToRight || got.class != classClosed {
		t.Fatalf("copyDir = %+v, want classClosed", got)
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
	// Hold Canceled until Transfer cancels. Both sides returning immediately
	// with Linger 0 lets a first-finishing Canceled cancel and drain boom.
	canceled := &holdCloser{closed: make(chan struct{}), err: context.Canceled}
	left := FDStream{R: canceled, W: io.Discard, C: canceled}
	right := FDStream{R: errorReader{err: want}, W: io.Discard, C: nopCloser{}}
	err := Transfer(context.Background(), left, right, Config{Linger: 0})
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
	err    error
}

func (h *holdCloser) Read([]byte) (int, error) {
	<-h.closed
	if h.err != nil {
		return 0, h.err
	}
	return 0, io.EOF
}

func (h *holdCloser) Write(p []byte) (int, error) { return len(p), nil }

func (h *holdCloser) Close() error {
	h.once.Do(func() { close(h.closed) })
	return nil
}
