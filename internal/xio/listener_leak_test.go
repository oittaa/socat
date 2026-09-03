package xio

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

type trackingContext struct {
	done       chan struct{}
	err        error
	mu         sync.Mutex
	registered atomic.Int32
	active     atomic.Int32
}

func newTrackingContext() *trackingContext {
	return &trackingContext{
		done: make(chan struct{}),
	}
}

func (c *trackingContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *trackingContext) Done() <-chan struct{}       { return c.done }
func (c *trackingContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}
func (c *trackingContext) Value(key any) any { return nil }

func (c *trackingContext) cancel(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
		close(c.done)
	}
	c.mu.Unlock()
}

func (c *trackingContext) AfterFunc(f func()) func() bool {
	c.registered.Add(1)
	c.active.Add(1)

	var once sync.Once
	stopCh := make(chan struct{})

	go func() {
		select {
		case <-c.done:
			once.Do(func() {
				c.active.Add(-1)
				f()
			})
		case <-stopCh:
		}
	}()

	return func() bool {
		stopped := false
		once.Do(func() {
			close(stopCh)
			c.active.Add(-1)
			stopped = true
		})
		return stopped
	}
}

func parseSpecOrFatal(t *testing.T, val string) parse.Spec {
	t.Helper()
	s, err := parse.ParseSpec(val)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func parseChannelOrFatal(t *testing.T, val string) parse.Channel {
	t.Helper()
	ch, err := parse.ParseChannel(val)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

func TestOpenListenSessionForkReleasesWatcherOnClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tctx := newTrackingContext()
	spec := parseSpecOrFatal(t, "TCP-LISTEN:0,fork")
	o, err := OpenListenSession(tctx, spec, nil, ListenSession{Listener: ln, Label: "TCP-LISTEN"})
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}

	if tctx.registered.Load() != 1 {
		t.Fatalf("registered=%d, want 1", tctx.registered.Load())
	}
	if tctx.active.Load() != 1 {
		t.Fatalf("active=%d, want 1", tctx.active.Load())
	}

	if err := o.Close(); err != nil {
		t.Fatalf("o.Close: %v", err)
	}

	if tctx.active.Load() != 0 {
		t.Fatalf("active after Close=%d, want 0", tctx.active.Load())
	}

	// Verify listener is closed
	if _, aerr := ln.Accept(); aerr == nil {
		t.Fatal("listener remained open after o.Close()")
	}
}

func TestOpenListenSessionForkCancellationInterruptsAccept(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	tctx := newTrackingContext()
	spec := parseSpecOrFatal(t, "TCP-LISTEN:0,fork")
	o, err := OpenListenSession(tctx, spec, nil, ListenSession{Listener: ln, Label: "TCP-LISTEN"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()

	acceptErr := make(chan error, 1)
	go func() {
		_, aerr := o.Listener.Accept()
		acceptErr <- aerr
	}()

	tctx.cancel(context.Canceled)

	select {
	case aerr := <-acceptErr:
		if aerr == nil {
			t.Fatal("Accept succeeded; want error on cancellation")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not unblock on context cancellation")
	}

	if err := o.Close(); err != nil {
		t.Fatalf("o.Close: %v", err)
	}
	if tctx.active.Load() != 0 {
		t.Fatalf("active after Close=%d, want 0", tctx.active.Load())
	}
}

func TestOpenListenSessionConcurrentCancellationAndClose(t *testing.T) {
	for i := 0; i < 50; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		tctx := newTrackingContext()
		spec := parseSpecOrFatal(t, "TCP-LISTEN:0,fork")
		o, err := OpenListenSession(tctx, spec, nil, ListenSession{Listener: ln, Label: "TCP-LISTEN"})
		if err != nil {
			_ = ln.Close()
			t.Fatal(err)
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			tctx.cancel(context.Canceled)
		}()
		go func() {
			defer wg.Done()
			_ = o.Close()
		}()
		wg.Wait()

		if tctx.active.Load() != 0 {
			t.Fatalf("iteration %d: active=%d, want 0", i, tctx.active.Load())
		}
	}
}

func TestRunForkListenTimeoutReleasesWatcher(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tctx := newTrackingContext()
	spec := parseSpecOrFatal(t, "TCP-LISTEN:0,fork,accept-timeout=0.01")
	lo, err := OpenListenSession(tctx, spec, nil, ListenSession{Listener: ln, Label: "TCP-LISTEN"})
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}

	right := parseChannelOrFatal(t, "PIPE")
	g := &Global{Log: logx.New()}
	runErr := RunOpened(tctx, lo, right, g)
	if !errors.Is(runErr, ErrAcceptTimeout) {
		t.Fatalf("RunOpened err=%v, want ErrAcceptTimeout", runErr)
	}

	if tctx.registered.Load() == 0 {
		t.Fatal("no cancellation watchers were registered")
	}
	if tctx.active.Load() != 0 {
		t.Fatalf("active watchers after timeout=%d, want 0", tctx.active.Load())
	}
}

func TestRunForkListenTerminalAcceptErrorReleasesWatcher(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tctx := newTrackingContext()
	spec := parseSpecOrFatal(t, "TCP-LISTEN:0,fork")
	lo, err := OpenListenSession(tctx, spec, nil, ListenSession{Listener: ln, Label: "TCP-LISTEN"})
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}

	// Close listener before running so Accept immediately fails with a terminal error.
	_ = ln.Close()

	right := parseChannelOrFatal(t, "PIPE")
	g := &Global{Log: logx.New()}
	_ = RunOpened(tctx, lo, right, g)

	if tctx.registered.Load() == 0 {
		t.Fatal("no cancellation watchers were registered")
	}
	if tctx.active.Load() != 0 {
		t.Fatalf("active watchers after terminal error=%d, want 0", tctx.active.Load())
	}
}

func TestRunForkListenRightTimeoutReleasesWatcher(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tctx := newTrackingContext()
	spec := parseSpecOrFatal(t, "TCP-LISTEN:0,fork,accept-timeout=0.01")
	ro, err := OpenListenSession(tctx, spec, nil, ListenSession{Listener: ln, Label: "TCP-LISTEN"})
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()

	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()

	lo := &Opened{
		Kind:   KindReady,
		Stream: relay.NetStream{Conn: c1},
	}
	defer func() { _ = lo.Close() }()

	g := &Global{Log: logx.New()}
	runErr := runForkListenRight(tctx, lo, ro, g)
	if !errors.Is(runErr, ErrAcceptTimeout) {
		t.Fatalf("runForkListenRight err=%v, want ErrAcceptTimeout", runErr)
	}
	_ = ro.Close()

	if tctx.registered.Load() == 0 {
		t.Fatal("no cancellation watchers were registered")
	}
	if tctx.active.Load() != 0 {
		t.Fatalf("active watchers after timeout on right=%d, want 0", tctx.active.Load())
	}
}

func TestRunForkListenRightTerminalAcceptErrorReleasesWatcher(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tctx := newTrackingContext()
	spec := parseSpecOrFatal(t, "TCP-LISTEN:0,fork")
	ro, err := OpenListenSession(tctx, spec, nil, ListenSession{Listener: ln, Label: "TCP-LISTEN"})
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}

	_ = ln.Close()

	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()

	lo := &Opened{
		Kind:   KindReady,
		Stream: relay.NetStream{Conn: c1},
	}
	defer func() { _ = lo.Close() }()

	g := &Global{Log: logx.New()}
	_ = runForkListenRight(tctx, lo, ro, g)
	_ = ro.Close()

	if tctx.registered.Load() == 0 {
		t.Fatal("no cancellation watchers were registered")
	}
	if tctx.active.Load() != 0 {
		t.Fatalf("active watchers after terminal error on right=%d, want 0", tctx.active.Load())
	}
}

func TestTCPListenForkRepeatedTimeoutReleasesWatchers(t *testing.T) {
	// Live reproduction scenario: repeated TCP-LISTEN,fork ending through accept-timeout.
	tctx := newTrackingContext()
	right := parseChannelOrFatal(t, "PIPE")

	for i := 0; i < 5; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		spec := parseSpecOrFatal(t, fmt.Sprintf("TCP-LISTEN:%d,reuseaddr,fork,accept-timeout=0.01", ln.Addr().(*net.TCPAddr).Port))
		lo, err := OpenListenSession(tctx, spec, nil, ListenSession{Listener: ln, Label: "TCP-LISTEN"})
		if err != nil {
			_ = ln.Close()
			t.Fatal(err)
		}

		g := &Global{Log: logx.New()}
		runErr := RunOpened(tctx, lo, right, g)
		if !errors.Is(runErr, ErrAcceptTimeout) {
			t.Fatalf("run %d: err=%v, want ErrAcceptTimeout", i, runErr)
		}
		if tctx.active.Load() != 0 {
			t.Fatalf("run %d: active watchers remaining=%d, want 0", i, tctx.active.Load())
		}
	}

	if tctx.registered.Load() != 10 {
		t.Fatalf("total registrations=%d, want 10 (2 per run)", tctx.registered.Load())
	}
	if tctx.active.Load() != 0 {
		t.Fatalf("active watchers remaining after all runs=%d, want 0", tctx.active.Load())
	}
}
