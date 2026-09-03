package relay

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIdleClockSharesOneSleeperAndBroadcasts(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{}, 2)
	clock := newIdleClock(func() {
		entered <- struct{}{}
		<-release
	})
	first := clock.subscribe()
	second := clock.subscribe()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("idle clock did not start")
	}
	select {
	case <-entered:
		t.Fatal("idle clock started more than one sleeper")
	default:
	}

	firstTick := first.next()
	secondTick := second.next()
	release <- struct{}{}
	for name, tick := range map[string]<-chan struct{}{"first": firstTick, "second": secondTick} {
		select {
		case <-tick:
		case <-time.After(time.Second):
			t.Fatalf("%s subscriber did not receive tick", name)
		}
	}

	first.close()
	second.close()
	stopped := make(chan struct{})
	clock.stopped = stopped
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("idle clock did not enter its final sleep")
	}
	release <- struct{}{}

	select {
	case <-stopped:
	case <-time.After(time.Second):
		clock.mu.Lock()
		running, users := clock.running, clock.users
		clock.mu.Unlock()
		t.Fatalf("idle clock did not stop: running=%v users=%d", running, users)
	}
}

func TestCopyDirMarksActivityBeforeBlockedWrite(t *testing.T) {
	writeStarted := make(chan struct{})
	releaseWrite := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseWrite) }) }
	defer release()
	destination := FDStream{
		R: bytes.NewReader(nil),
		W: blockingTestWriter{
			started: writeStarted,
			release: releaseWrite,
		},
	}
	source := FDStream{R: bytes.NewReader([]byte("payload"))}

	activity := make(chan struct{})
	var activityOnce sync.Once
	touch := func() { activityOnce.Do(func() { close(activity) }) }
	var transferred, blocks atomic.Uint64
	results := make(chan dirResult, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go copyDir(context.Background(), dirTask{
		dir:    ">",
		dst:    destination,
		src:    source,
		dstFD:  -1,
		srcFD:  -1,
		bytes:  &transferred,
		blocks: &blocks,
	}, Config{BufferSize: 8192}, touch, results, &wg)

	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("write did not start")
	}
	select {
	case <-activity:
	case <-time.After(time.Second):
		t.Fatal("read did not mark activity before the blocked write")
	}
	release()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("copy did not finish")
	}
	if result := <-results; result.err != nil {
		t.Fatal(result.err)
	}
}

type blockingTestWriter struct {
	started chan struct{}
	release chan struct{}
}

func (w blockingTestWriter) Write(p []byte) (int, error) {
	close(w.started)
	<-w.release
	return len(p), nil
}
