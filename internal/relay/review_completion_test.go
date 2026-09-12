package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type startDirFn func(context.Context, dirTask, Config, func(), chan<- dirOutcome, *sync.WaitGroup)

type completionCase struct {
	name      string
	copyErr   error
	wantClass dirClass
	fallback  bool
}

func TestReviewOutcomePublishedAfterCleanup(t *testing.T) {
	cases := []completionCase{
		{name: "eof", wantClass: classEOF},
		{name: "dest-close", copyErr: io.ErrClosedPipe, wantClass: classClosed},
		{name: "cancel", copyErr: context.Canceled, wantClass: classCanceled},
		{name: "failure", copyErr: errors.New("boom"), wantClass: classFailed},
		{name: "unsupported-zero-copy-fallback", copyErr: errZeroCopyUnsupported, wantClass: classEOF, fallback: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runReviewCompletion(t, startDir, tc, true)
		})
	}
	t.Run("startDirBeforeCleanup", func(t *testing.T) {
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				runReviewCompletion(t, startDirBeforeCleanup, tc, false)
			})
		}
	})
}

func runReviewCompletion(t *testing.T, start startDirFn, tc completionCase, wantAfterCleanup bool) {
	t.Helper()
	wait, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	plan := newBlockingPlan(tc.copyErr)
	t.Cleanup(plan.releaseClose)

	const payload = "payload"
	var (
		copied          bytes.Buffer
		bytesN, blocksN atomic.Uint64
		eofs, shutdowns atomic.Int32
	)
	task := dirTask{
		dir:    dirLeftToRight,
		src:    FDStream{R: strings.NewReader(payload), W: io.Discard, C: nopCloser{}},
		dst:    memStream{r: eofReader{}, w: &copied, shutdowns: &shutdowns},
		dstFD:  -1,
		srcFD:  -1,
		plan:   plan,
		bytes:  &bytesN,
		blocks: &blocksN,
	}
	cfg := Config{
		BufferSize: 32,
		OnEOF:      func(_, _ int) { eofs.Add(1) },
	}
	results := make(chan dirOutcome, 1)
	var wg sync.WaitGroup
	start(context.Background(), task, cfg, func() {}, results, &wg)

	select {
	case <-plan.closeEntered:
	case <-wait.Done():
		t.Fatal("Close was not entered")
	}

	got, published := tryRecv(results)
	if wantAfterCleanup && published {
		t.Fatalf("published before cleanup: %+v", got)
	}
	if !wantAfterCleanup && !published {
		t.Fatal("inverted helper did not publish before cleanup")
	}
	if tc.fallback {
		if wantAfterCleanup {
			assertFallbackIdle(t, copied.String(), bytesN.Load(), blocksN.Load(), eofs.Load(), shutdowns.Load())
		} else {
			assertFallbackDone(t, copied.String(), bytesN.Load(), blocksN.Load(), eofs.Load(), shutdowns.Load())
		}
	}

	plan.releaseClose()
	if !published {
		select {
		case got = <-results:
		case <-wait.Done():
			t.Fatal("no result after Close")
		}
	}
	waitWG(t, wait, &wg)

	if n := plan.closes.Load(); n != 1 {
		t.Fatalf("cleanup count = %d, want 1", n)
	}
	if got.dir != dirLeftToRight || got.class != tc.wantClass {
		t.Fatalf("outcome = %+v, want class %v", got, tc.wantClass)
	}
	if tc.wantClass == classFailed && (got.err == nil || got.err.Error() != "boom") {
		t.Fatalf("failure err = %v, want boom", got.err)
	}
	if tc.fallback && wantAfterCleanup {
		assertFallbackDone(t, copied.String(), bytesN.Load(), blocksN.Load(), eofs.Load(), shutdowns.Load())
	}
}

func assertFallbackIdle(t *testing.T, payload string, bytesN, blocksN uint64, eofs, shutdowns int32) {
	t.Helper()
	if payload != "" || bytesN != 0 || blocksN != 0 || eofs != 0 || shutdowns != 0 {
		t.Fatalf("fallback ran before Close: payload=%q bytes=%d blocks=%d eofs=%d shutdowns=%d",
			payload, bytesN, blocksN, eofs, shutdowns)
	}
}

func assertFallbackDone(t *testing.T, payload string, bytesN, blocksN uint64, eofs, shutdowns int32) {
	t.Helper()
	if payload != "payload" || bytesN != uint64(len("payload")) || blocksN != 1 || eofs != 1 || shutdowns != 1 {
		t.Fatalf("fallback after copy: payload=%q bytes=%d blocks=%d eofs=%d shutdowns=%d",
			payload, bytesN, blocksN, eofs, shutdowns)
	}
}

func tryRecv(results <-chan dirOutcome) (dirOutcome, bool) {
	select {
	case got := <-results:
		return got, true
	default:
		return dirOutcome{}, false
	}
}

func waitWG(t *testing.T, ctx context.Context, wg *sync.WaitGroup) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("worker did not finish")
	}
}

// startDirBeforeCleanup is the old send-then-cleanup order. The after-cleanup
// assertions fail on this helper; startDir must not.
func startDirBeforeCleanup(ctx context.Context, t dirTask, cfg Config, touch func(), results chan<- dirOutcome, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		out := copyDirLeaveOpen(ctx, t, cfg, touch)
		results <- out
		if t.plan != nil {
			_ = t.plan.Close()
		}
	}()
}

func copyDirLeaveOpen(ctx context.Context, t dirTask, cfg Config, touch func()) dirOutcome {
	if t.plan != nil {
		if o, ok := copyZeroCopyLeaveOpen(ctx, t, cfg, touch); ok {
			return o
		}
	}
	return copyBuffered(ctx, t, cfg, touch)
}

func copyZeroCopyLeaveOpen(ctx context.Context, t dirTask, cfg Config, touch func()) (dirOutcome, bool) {
	onRead := func(n int64) {
		if n <= 0 {
			return
		}
		touch()
		t.blocks.Add(configuredBlockCount(n, cfg.BufferSize))
	}
	onWrite := func(n int64) {
		if n > 0 {
			t.bytes.Add(uint64(n))
		}
	}
	err := t.plan.Copy(ctx, onRead, onWrite)
	if errors.Is(err, errZeroCopyUnsupported) {
		return dirOutcome{}, false
	}
	if err == nil {
		return finishSourceEOF(ctx, t, cfg), true
	}
	if isBenignClose(err) {
		return dirClosed(t.dir), true
	}
	return classifyDirError(t.dir, err), true
}

type blockingPlan struct {
	copyErr      error
	closeEntered chan struct{}
	release      chan struct{}
	releaseOnce  sync.Once
	closes       atomic.Int32
}

func newBlockingPlan(copyErr error) *blockingPlan {
	return &blockingPlan{
		copyErr:      copyErr,
		closeEntered: make(chan struct{}),
		release:      make(chan struct{}),
	}
}

func (p *blockingPlan) Copy(context.Context, func(int64), func(int64)) error {
	return p.copyErr
}

func (p *blockingPlan) Close() error {
	p.closes.Add(1)
	p.closeEntered <- struct{}{}
	<-p.release
	return nil
}

func (p *blockingPlan) releaseClose() {
	p.releaseOnce.Do(func() { close(p.release) })
}

type memStream struct {
	r         io.Reader
	w         io.Writer
	shutdowns *atomic.Int32
}

func (s memStream) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s memStream) Write(p []byte) (int, error) { return s.w.Write(p) }
func (s memStream) Close() error                { return nil }
func (s memStream) StreamProps() Props          { return NoProps() }

func (s memStream) ShutdownWrite() error {
	if s.shutdowns != nil {
		s.shutdowns.Add(1)
	}
	return nil
}
