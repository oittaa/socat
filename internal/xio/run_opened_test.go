package xio

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

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

	t.Run("left accept does not open right", func(t *testing.T) {
		ln := newCloseOnlyListener()
		t.Cleanup(func() { _ = ln.Close() })
		lo, err := NewAcceptParent("accept", AcceptParent{Listener: ln})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := RunOpenedPrepared(ctx, lo, empty, g); err != nil {
			t.Fatalf("accept parent opened right or left the listen path: %v", err)
		}
	})

	t.Run("left dial does not open right", func(t *testing.T) {
		lo, err := NewRepeatedDial("dial", RepeatedDial{
			Dial: func(context.Context) (net.Conn, error) { return nil, context.Canceled },
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := RunOpenedPrepared(ctx, lo, empty, g); err != nil {
			t.Fatalf("dial parent opened right or left the connect path: %v", err)
		}
	})

	t.Run("left nofork opens right first", func(t *testing.T) {
		lo := NewDeferredNoFork("nofork", addrconfig.Address{Type: "EXEC"})
		err := RunOpenedPrepared(context.Background(), lo, empty, g)
		if err == nil || !strings.Contains(err.Error(), "empty channel") {
			t.Fatalf("nofork left should open right: %v", err)
		}
	})
}

func TestRunOpenedPairDispatchesOnPayload(t *testing.T) {
	g := &Global{Log: logx.New(), BlockSize: 8192}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	left, err := NewReady("left", relay.FDStream{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = left.Close() })

	t.Run("right accept", func(t *testing.T) {
		ln := newCloseOnlyListener()
		t.Cleanup(func() { _ = ln.Close() })
		ro, err := NewAcceptParent("accept", AcceptParent{Listener: ln})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ro.Close() })
		if err := runOpenedPair(ctx, left, ro, g, ModeRDWR, ModeRDWR); err != nil {
			t.Fatalf("right accept took transfer path: %v", err)
		}
	})

	t.Run("right dial", func(t *testing.T) {
		ro, err := NewRepeatedDial("dial", RepeatedDial{
			Dial: func(context.Context) (net.Conn, error) { return nil, context.Canceled },
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ro.Close() })
		if err := runOpenedPair(ctx, left, ro, g, ModeRDWR, ModeRDWR); err != nil {
			t.Fatalf("right dial took transfer path: %v", err)
		}
	})

	t.Run("left nofork", func(t *testing.T) {
		lo := NewDeferredNoFork("nofork", addrconfig.Address{Type: "EXEC"})
		t.Cleanup(func() { _ = lo.Close() })
		ro, err := NewReady("right", relay.FDStream{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ro.Close() })
		err = runOpenedPair(context.Background(), lo, ro, g, ModeRDWR, ModeRDWR)
		if err == nil || strings.Contains(err.Error(), "nil stream") {
			t.Fatalf("left nofork took transfer path: %v", err)
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
}
