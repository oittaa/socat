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
	"testing/synctest"
)

func TestOutcomePublishedAfterCleanup(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		class dirClass
	}{
		{"eof", nil, classEOF},
		{"closed", io.ErrClosedPipe, classClosed},
		{"canceled", context.Canceled, classCanceled},
		{"failed", errors.New("copy failed"), classFailed},
		{"fallback", errZeroCopyUnsupported, classEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				plan := &blockingPlan{err: tc.err, release: make(chan struct{})}
				defer close(plan.release)
				var copied bytes.Buffer
				task := dirTask{
					src: FDStream{R: strings.NewReader("payload")}, dst: FDStream{W: &copied},
					srcFD: -1, dstFD: -1, plan: plan, bytes: new(atomic.Uint64), blocks: new(atomic.Uint64),
				}
				results := make(chan dirOutcome, 1)
				var wg sync.WaitGroup
				startDir(t.Context(), task, Config{BufferSize: 32}, func() {}, results, &wg)
				synctest.Wait()
				if plan.closes != 1 || len(results) != 0 || copied.Len() != 0 {
					t.Fatalf("before cleanup: closes=%d results=%d copied=%q", plan.closes, len(results), copied.String())
				}
				plan.release <- struct{}{}
				wg.Wait()
				if got := <-results; got.class != tc.class || plan.closes != 1 {
					t.Fatalf("outcome=%+v closes=%d; want class %v, one close", got, plan.closes, tc.class)
				}
				if tc.err == errZeroCopyUnsupported && copied.String() != "payload" {
					t.Fatalf("fallback copied %q", copied.String())
				}
			})
		})
	}
}

type blockingPlan struct {
	err     error
	release chan struct{}
	closes  int
}

func (p *blockingPlan) Copy(context.Context, func(int64), func(int64)) error { return p.err }
func (p *blockingPlan) Close() error {
	p.closes++
	<-p.release
	return nil
}
