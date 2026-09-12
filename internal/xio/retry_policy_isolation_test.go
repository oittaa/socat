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

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

var errRetryAgain = errors.New("retry again")

func retrySession() *Global {
	return NewSession(Options{BlockSize: 8192}, logx.New())
}

func decodeRetrySpec(t *testing.T, spec string) addrconfig.Address {
	t.Helper()
	raw, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	config, err := addrconfig.Decode(raw, addrconfig.Facts{Type: raw.Type, Caps: CapsTCPConnect})
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func fastRetryPolicy(p addrconfig.RetryPolicy) addrconfig.RetryPolicy {
	p.Interval = 0
	return p
}

func waitSignal(t *testing.T, ctx context.Context, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-ctx.Done():
		t.Fatalf("waiting for %s: %v", what, ctx.Err())
	}
}

func isolatedAttemptsError(left, right, wantLeft, wantRight int64) error {
	if left != wantLeft || right != wantRight {
		return fmt.Errorf("attempts left=%d want %d; right=%d want %d", left, wantLeft, right, wantRight)
	}
	return nil
}

func sharedPolicyAttempts(left, right addrconfig.RetryPolicy) (int64, int64) {
	_ = right
	var n atomic.Int64
	_ = WithRetry(context.Background(), nil, left, "shared", func() error {
		n.Add(1)
		return errRetryAgain
	})
	got := n.Load()
	return got, got
}

type retryProbe struct {
	attempts atomic.Int64
	live     atomic.Int64
	doneOnce sync.Once
	done     chan struct{}
}

func newRetryProbe() *retryProbe {
	return &retryProbe{done: make(chan struct{})}
}

func (p *retryProbe) finish() {
	p.doneOnce.Do(func() { close(p.done) })
}

func (p *retryProbe) exhaustOpener(hold <-chan struct{}) Opener {
	return func(ctx context.Context, s addrconfig.Address, _ Mode, g *Global) (*Opened, error) {
		p.live.Add(1)
		defer p.live.Add(-1)
		err := WithRetry(ctx, g, fastRetryPolicy(s.Common.Retry.Policy()), s.Type, func() error {
			p.attempts.Add(1)
			return errRetryAgain
		})
		p.finish()
		if hold != nil {
			select {
			case <-hold:
			case <-ctx.Done():
			}
		}
		return nil, err
	}
}

func openRetryConnectFork(t *testing.T, spec string, attempts *atomic.Int64, g *Global) *Opened {
	t.Helper()
	config := decodeRetrySpec(t, spec)
	var leftover net.Conn
	t.Cleanup(func() {
		if leftover != nil {
			_ = leftover.Close()
		}
	})
	opened, err := OpenDialed(context.Background(), config, g, Dialed{
		Label: "left-retry",
		Dial: func(ctx context.Context) (net.Conn, error) {
			var conn net.Conn
			err := WithRetry(ctx, g, fastRetryPolicy(config.Common.Retry.Policy()), config.Type, func() error {
				n := attempts.Add(1)
				policy := config.Common.Retry.Policy()
				if policy.MaxAttempts != 0 && uint64(n) < policy.MaxAttempts {
					return errRetryAgain
				}
				a, b := net.Pipe()
				leftover = b
				conn = a
				return nil
			})
			return conn, err
		},
		Wrap: func(c net.Conn) (relay.Stream, error) {
			return relay.NetStream{Conn: c}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	return opened
}

func TestRetryIsolationContractRejectsAliasedCounts(t *testing.T) {
	if err := isolatedAttemptsError(2, 2, 2, 4); err == nil {
		t.Fatal("aliased left/right counts must fail isolation")
	}
	if err := isolatedAttemptsError(2, 4, 2, 4); err != nil {
		t.Fatal(err)
	}
}

func TestSharedRetryPolicyAliasesAttemptCounts(t *testing.T) {
	left := addrconfig.RetryPolicy{MaxAttempts: 2}
	right := addrconfig.RetryPolicy{MaxAttempts: 4}
	gotLeft, gotRight := sharedPolicyAttempts(left, right)
	if err := isolatedAttemptsError(gotLeft, gotRight, int64(left.MaxAttempts), int64(right.MaxAttempts)); err == nil {
		t.Fatal("shared policy unexpectedly satisfied isolation")
	}
	if gotLeft != int64(left.MaxAttempts) || gotRight != int64(left.MaxAttempts) {
		t.Fatalf("shared policy left=%d right=%d want both %d", gotLeft, gotRight, left.MaxAttempts)
	}
}

func TestLeftRightRetryPoliciesIsolatedThroughForkedDialing(t *testing.T) {
	const (
		leftSpec  = "TCP:127.0.0.1:9,fork,retry=1,interval=1h,max-children=1"
		rightSpec = "TCP:127.0.0.1:9,retry=3,interval=0"
	)
	wantLeft := int64(decodeRetrySpec(t, leftSpec).Common.Retry.Policy().MaxAttempts)
	wantRight := int64(decodeRetrySpec(t, rightSpec).Common.Retry.Policy().MaxAttempts)
	if wantLeft == wantRight || wantLeft < 2 || wantRight < 2 {
		t.Fatalf("fixture policies left=%d right=%d", wantLeft, wantRight)
	}

	t.Run("connectFork", func(t *testing.T) {
		g := retrySession()
		var leftAttempts atomic.Int64
		right := newRetryProbe()
		hold := make(chan struct{})
		lo := openRetryConnectFork(t, leftSpec, &leftAttempts, g)
		rightPrepared := PreparedAddress{Config: decodeRetrySpec(t, rightSpec), opener: right.exhaustOpener(hold)}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		finished := make(chan error, 1)
		go func() {
			finished <- RunOpenedPrepared(ctx, lo, PreparedChannel{Single: &rightPrepared}, g)
		}()
		waitSignal(t, ctx, right.done, "right retry exhaustion")
		if err := isolatedAttemptsError(leftAttempts.Load(), right.attempts.Load(), wantLeft, wantRight); err != nil {
			t.Fatal(err)
		}
		cancel()
		select {
		case err := <-finished:
			if err != nil {
				t.Fatalf("run: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("run did not terminate after cancel")
		}
		if live := right.live.Load(); live != 0 {
			t.Fatalf("orphaned right worker live=%d", live)
		}
	})

	t.Run("listenFork", func(t *testing.T) {
		g := retrySession()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		lo, err := NewAcceptParent("left-listen", AcceptParent{Listener: ln, MaxChildren: 1})
		if err != nil {
			t.Fatal(err)
		}
		right := newRetryProbe()
		hold := make(chan struct{})
		rightPrepared := PreparedAddress{Config: decodeRetrySpec(t, rightSpec), opener: right.exhaustOpener(hold)}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		finished := make(chan error, 1)
		go func() {
			finished <- RunOpenedPrepared(ctx, lo, PreparedChannel{Single: &rightPrepared}, g)
		}()
		client, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		waitSignal(t, ctx, right.done, "deferred right retry exhaustion")
		if got := right.attempts.Load(); got != wantRight {
			t.Fatalf("deferred right attempts=%d want %d (left policy %d)", got, wantRight, wantLeft)
		}
		if right.attempts.Load() == wantLeft {
			t.Fatal("right used left retry policy")
		}
		cancel()
		select {
		case err := <-finished:
			if err != nil {
				t.Fatalf("run: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("run did not terminate after cancel")
		}
		if live := right.live.Load(); live != 0 {
			t.Fatalf("orphaned right worker live=%d", live)
		}
	})
}

func TestCancelDuringRetryStopsAttemptsAndWorkers(t *testing.T) {
	g := retrySession()
	var leftAttempts atomic.Int64
	lo := openRetryConnectFork(t, "TCP:127.0.0.1:9,fork,interval=1h,max-children=1", &leftAttempts, g)

	var attempts, live atomic.Int64
	started := make(chan struct{})
	right := PreparedAddress{
		Config: decodeRetrySpec(t, "TCP:127.0.0.1:9,forever,interval=0"),
		opener: func(ctx context.Context, s addrconfig.Address, _ Mode, g *Global) (*Opened, error) {
			live.Add(1)
			defer live.Add(-1)
			policy := fastRetryPolicy(s.Common.Retry.Policy())
			return nil, WithRetry(ctx, g, policy, s.Type, func() error {
				if attempts.Add(1) == 1 {
					close(started)
				}
				var never <-chan struct{}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-never:
					return errRetryAgain
				}
			})
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		finished <- RunOpenedPrepared(ctx, lo, PreparedChannel{Single: &right}, g)
	}()
	waitSignal(t, ctx, started, "first retry attempt")
	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts before cancel=%d", got)
	}
	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not terminate after cancel")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts after cancel=%d want 1", got)
	}
	if got := live.Load(); got != 0 {
		t.Fatalf("orphaned worker live=%d", got)
	}
	if got := leftAttempts.Load(); got != 1 {
		t.Fatalf("left attempts=%d want 1", got)
	}
}
