package xio

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

var (
	errAcceptSentinel = errors.New("dispatch: accept sentinel")
	errDialSentinel   = errors.New("dispatch: dial sentinel")
)

type recordListener struct {
	n int
}

func (l *recordListener) Accept() (net.Conn, error) {
	l.n++
	return nil, errAcceptSentinel
}

func (l *recordListener) Close() error   { return nil }
func (l *recordListener) Addr() net.Addr { return &net.TCPAddr{} }

func recordDial(n *int) func(context.Context) (net.Conn, error) {
	return func(context.Context) (net.Conn, error) {
		*n++
		return nil, errDialSentinel
	}
}

func liveDispatchCtx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 2*time.Second)
}

func TestRunOpenedClosesLeftWhenRightPrepareFails(t *testing.T) {
	lo, err := NewReady("", relay.FDStream{})
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	lo.AddCleanup(func() { closed = true })
	ch, err := parse.ParseChannel("NOSUCH:x")
	if err != nil {
		t.Fatal(err)
	}
	err = RunOpened(context.Background(), lo, ch, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown device/address") {
		t.Fatalf("error=%v", err)
	}
	if !closed {
		t.Fatal("left endpoint was not closed")
	}
}

func TestRunOpenedNilLeftOnPrepareFailure(t *testing.T) {
	ch, err := parse.ParseChannel("NOSUCH:x")
	if err != nil {
		t.Fatal(err)
	}
	err = RunOpened(context.Background(), nil, ch, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown device/address") {
		t.Fatalf("error=%v", err)
	}
}

func TestRunOpenedPreparedDispatchesOnPayload(t *testing.T) {
	g := &Global{Log: logx.New(), BlockSize: 8192}
	empty := PreparedChannel{}

	t.Run("left accept uses listener", func(t *testing.T) {
		ln := &recordListener{}
		lo, err := NewAcceptParent("accept", AcceptParent{Listener: ln})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := liveDispatchCtx(t)
		defer cancel()
		err = RunOpenedPrepared(ctx, lo, empty, g)
		if !errors.Is(err, errAcceptSentinel) {
			t.Fatalf("left accept: %v", err)
		}
		if ln.n != 1 {
			t.Fatalf("Accept calls=%d", ln.n)
		}
	})

	t.Run("left dial uses dialer", func(t *testing.T) {
		var n int
		lo, err := NewRepeatedDial("dial", RepeatedDial{Dial: recordDial(&n)})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := liveDispatchCtx(t)
		defer cancel()
		err = RunOpenedPrepared(ctx, lo, empty, g)
		if !errors.Is(err, errDialSentinel) {
			t.Fatalf("left dial: %v", err)
		}
		if n != 1 {
			t.Fatalf("Dial calls=%d", n)
		}
	})

	t.Run("left nofork opens right first", func(t *testing.T) {
		lo := NewDeferredNoFork("nofork", addrconfig.Address{Type: "EXEC"})
		err := RunOpenedPrepared(context.Background(), lo, empty, g)
		if err == nil || !strings.Contains(err.Error(), "empty channel") {
			t.Fatalf("nofork left should open right: %v", err)
		}
	})

	t.Run("left accept canceled before accept", func(t *testing.T) {
		ln := newCloseOnlyListener()
		t.Cleanup(func() { _ = ln.Close() })
		lo, err := NewAcceptParent("accept", AcceptParent{Listener: ln})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := RunOpenedPrepared(ctx, lo, empty, g); err != nil {
			t.Fatalf("canceled left accept: %v", err)
		}
	})

	t.Run("left dial canceled before dial", func(t *testing.T) {
		var n int
		lo, err := NewRepeatedDial("dial", RepeatedDial{Dial: recordDial(&n)})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := RunOpenedPrepared(ctx, lo, empty, g); err != nil {
			t.Fatalf("canceled left dial: %v", err)
		}
		if n != 0 {
			t.Fatalf("canceled left dial called Dial %d times", n)
		}
	})
}

func TestRunOpenedPairDispatchesOnPayload(t *testing.T) {
	g := &Global{Log: logx.New(), BlockSize: 8192}
	left, err := NewReady("left", relay.FDStream{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = left.Close() })

	t.Run("right accept uses listener", func(t *testing.T) {
		ln := &recordListener{}
		ro, err := NewAcceptParent("accept", AcceptParent{Listener: ln})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ro.Close() })
		ctx, cancel := liveDispatchCtx(t)
		defer cancel()
		err = runOpenedPair(ctx, left, ro, g, ModeRDWR, ModeRDWR)
		if !errors.Is(err, errAcceptSentinel) {
			t.Fatalf("right accept: %v", err)
		}
		if ln.n != 1 {
			t.Fatalf("Accept calls=%d", ln.n)
		}
	})

	t.Run("right dial uses dialer", func(t *testing.T) {
		var n int
		ro, err := NewRepeatedDial("dial", RepeatedDial{Dial: recordDial(&n)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ro.Close() })
		ctx, cancel := liveDispatchCtx(t)
		defer cancel()
		err = runOpenedPair(ctx, left, ro, g, ModeRDWR, ModeRDWR)
		if !errors.Is(err, errDialSentinel) {
			t.Fatalf("right dial: %v", err)
		}
		if n != 1 {
			t.Fatalf("Dial calls=%d", n)
		}
	})

	t.Run("left nofork precedes right accept", func(t *testing.T) {
		ln := &recordListener{}
		lo := NewDeferredNoFork("nofork", addrconfig.Address{Type: "EXEC"})
		t.Cleanup(func() { _ = lo.Close() })
		ro, err := NewAcceptParent("accept", AcceptParent{Listener: ln})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ro.Close() })
		err = runOpenedPair(context.Background(), lo, ro, g, ModeRDWR, ModeRDWR)
		if err == nil || errors.Is(err, errAcceptSentinel) || strings.Contains(err.Error(), "nil stream") {
			t.Fatalf("left nofork lost precedence: %v", err)
		}
		if ln.n != 0 {
			t.Fatalf("nofork called Accept %d times", ln.n)
		}
	})

	t.Run("left nofork precedes right dial", func(t *testing.T) {
		var n int
		lo := NewDeferredNoFork("nofork", addrconfig.Address{Type: "EXEC"})
		t.Cleanup(func() { _ = lo.Close() })
		ro, err := NewRepeatedDial("dial", RepeatedDial{Dial: recordDial(&n)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ro.Close() })
		err = runOpenedPair(context.Background(), lo, ro, g, ModeRDWR, ModeRDWR)
		if err == nil || errors.Is(err, errDialSentinel) || strings.Contains(err.Error(), "nil stream") {
			t.Fatalf("left nofork lost precedence: %v", err)
		}
		if n != 0 {
			t.Fatalf("nofork called Dial %d times", n)
		}
	})

	t.Run("right nofork", func(t *testing.T) {
		ro := NewDeferredNoFork("nofork", addrconfig.Address{Type: "EXEC"})
		t.Cleanup(func() { _ = ro.Close() })
		err := runOpenedPair(context.Background(), left, ro, g, ModeRDWR, ModeRDWR)
		if err == nil || strings.Contains(err.Error(), "nil stream") {
			t.Fatalf("right nofork took transfer path: %v", err)
		}
	})

	t.Run("right accept canceled before accept", func(t *testing.T) {
		ln := newCloseOnlyListener()
		t.Cleanup(func() { _ = ln.Close() })
		ro, err := NewAcceptParent("accept", AcceptParent{Listener: ln})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ro.Close() })
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := runOpenedPair(ctx, left, ro, g, ModeRDWR, ModeRDWR); err != nil {
			t.Fatalf("canceled right accept: %v", err)
		}
	})

	t.Run("right dial canceled before dial", func(t *testing.T) {
		var n int
		ro, err := NewRepeatedDial("dial", RepeatedDial{Dial: recordDial(&n)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ro.Close() })
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := runOpenedPair(ctx, left, ro, g, ModeRDWR, ModeRDWR); err != nil {
			t.Fatalf("canceled right dial: %v", err)
		}
		if n != 0 {
			t.Fatalf("canceled right dial called Dial %d times", n)
		}
	})
}
