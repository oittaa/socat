package xio

import (
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// A non-nil Done also exercises cancellation registrations that need stopping.
// Unlike a test-scoped context, this parent stays open when the test ends.
type listenerLifetimeContext struct {
	context.Context
	done <-chan struct{}
}

func (c listenerLifetimeContext) Done() <-chan struct{} { return c.done }

func testListenerLifetime(t *testing.T, run func(*testing.T, context.Context)) {
	t.Helper()
	for _, name := range []string{"background", "open-done"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := context.Background()
				if name == "open-done" {
					ctx = listenerLifetimeContext{Context: ctx, done: make(chan struct{})}
				}
				// synctest requires every goroutine started here to exit. An old
				// <-ctx.Done() watcher fails even without an AfterFunc registration.
				run(t, ctx)
			})
		})
	}
}

func openForkListenerForLifetime(t *testing.T, ctx context.Context) (*Opened, *closeOnlyListener) {
	t.Helper()
	ln := newCloseOnlyListener()
	t.Cleanup(func() { _ = ln.Close() })
	spec := parseSpecForListenSession(t, "TCP-LISTEN:0,fork,accept-timeout=0.01")
	o, err := OpenListenSession(ctx, mustDecodeAddress(t, spec), nil, ListenSession{Listener: ln, Label: "TCP-LISTEN"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o, ln
}

func TestOpenListenSessionForkReleasesWatcherOnClose(t *testing.T) {
	testListenerLifetime(t, func(t *testing.T, ctx context.Context) {
		o, ln := openForkListenerForLifetime(t, ctx)
		if err := o.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		select {
		case <-ln.closed:
		default:
			t.Fatal("listener remained open after Close")
		}
	})
}

func TestRunForkListenReleasesWatchers(t *testing.T) {
	testForkListenerExit(t, false)
}

func TestRunForkListenRightReleasesWatchers(t *testing.T) {
	testForkListenerExit(t, true)
}

func testForkListenerExit(t *testing.T, rightSide bool) {
	t.Helper()
	for _, exit := range []string{"timeout", "accept-error"} {
		t.Run(exit, func(t *testing.T) {
			testListenerLifetime(t, func(t *testing.T, ctx context.Context) {
				// Reuse the uncanceled parent across repeated listener lifetimes.
				for range 5 {
					o, ln := openForkListenerForLifetime(t, ctx)
					wantErr := ErrAcceptTimeout
					if exit == "accept-error" {
						_ = ln.Close()
						wantErr = net.ErrClosed
					}
					g := &Global{Log: logx.New()}
					var runErr error
					if rightSide {
						c1, c2 := net.Pipe()
						left := NewReady("", relay.NetStream{Conn: c1})
						runErr = runForkListenRight(ctx, left, o, g)
						_ = left.Close()
						_ = c2.Close()
					} else {
						right, err := parse.ParseChannel("PIPE")
						if err != nil {
							t.Fatal(err)
						}
						runErr = RunOpened(ctx, o, right, g)
					}
					if !errors.Is(runErr, wantErr) {
						t.Fatalf("accept loop error=%v, want %v", runErr, wantErr)
					}
					if err := o.Close(); err != nil {
						t.Fatalf("Close after accept loop: %v", err)
					}
				}
			})
		})
	}
}
