package xio

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
)

func retrySession() *Global {
	lg := logx.New()
	lg.SetOutput(io.Discard)
	return NewSession(Options{BlockSize: 8192}, lg)
}

func prepareChannel(t *testing.T, spec string) PreparedChannel {
	t.Helper()
	raw, err := parse.ParseChannel(spec)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareChannel(raw)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func requireRetryAttempts(t *testing.T, ch PreparedChannel, want uint64) {
	t.Helper()
	got := ch.Single.Config.Common.Retry.Policy().MaxAttempts
	if got != want {
		t.Fatalf("policy MaxAttempts=%d want %d", got, want)
	}
}

func reservedTCP4Addr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ta, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = ln.Close()
		t.Fatalf("listen addr %T", ln.Addr())
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(ta.Port))
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func listenTCP4(addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				sockErr = setSockoptInt(int(fd), solSocket, soReuseaddr, 1)
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	return lc.Listen(context.Background(), "tcp4", addr)
}

func waitConn(t *testing.T, ctx context.Context, ch <-chan net.Conn, what string) net.Conn {
	t.Helper()
	select {
	case c := <-ch:
		t.Cleanup(func() { _ = c.Close() })
		return c
	case <-ctx.Done():
		t.Fatalf("waiting for %s: %v", what, ctx.Err())
		return nil
	}
}

func waitErr(t *testing.T, ch <-chan error, d time.Duration, what string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(d):
		t.Fatalf("%s did not finish", what)
		return nil
	}
}

func writeRead(t *testing.T, w, r net.Conn, msg []byte) {
	t.Helper()
	_ = w.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_ = r.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := w.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("handoff %q want %q", got, msg)
	}
}

// destGate is a reserved TCP4 port. startAfter>0 binds after that many
// production DialTCPAll results so a later attempt can succeed.
type destGate struct {
	addr       string
	startAfter int64
	mu         sync.Mutex
	cond       *sync.Cond
	dials      int64
	startOnce  sync.Once
	ln         net.Listener
	accepted   chan net.Conn
	startErr   error
	closed     atomic.Bool
}

func newDestGate(addr string, startAfter uint64) *destGate {
	g := &destGate{
		addr:       addr,
		startAfter: int64(startAfter),
		accepted:   make(chan net.Conn, 1),
	}
	g.cond = sync.NewCond(&g.mu)
	return g
}

func (g *destGate) onDial(error) {
	g.mu.Lock()
	g.dials++
	n := g.dials
	g.cond.Broadcast()
	g.mu.Unlock()
	if g.startAfter > 0 && n == g.startAfter {
		g.startListen()
	}
}

func (g *destGate) loadDials() int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.dials
}

func (g *destGate) waitDials(t *testing.T, ctx context.Context, want int64, what string) {
	t.Helper()
	stop := context.AfterFunc(ctx, func() {
		g.cond.Broadcast()
	})
	defer stop()
	g.mu.Lock()
	defer g.mu.Unlock()
	for g.dials < want {
		if err := ctx.Err(); err != nil {
			t.Fatalf("waiting for %s dials=%d want %d: %v", what, g.dials, want, err)
		}
		g.cond.Wait()
	}
}

func (g *destGate) startListen() {
	g.startOnce.Do(func() {
		if g.closed.Load() {
			return
		}
		ln, err := listenTCP4(g.addr)
		g.mu.Lock()
		if err != nil {
			g.startErr = err
			g.mu.Unlock()
			return
		}
		g.ln = ln
		g.mu.Unlock()
		go g.acceptLoop()
	})
}

func (g *destGate) acceptLoop() {
	g.mu.Lock()
	ln := g.ln
	g.mu.Unlock()
	if ln == nil {
		return
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case g.accepted <- c:
		default:
			_ = c.Close()
		}
	}
}

func (g *destGate) close() {
	g.closed.Store(true)
	g.mu.Lock()
	ln := g.ln
	g.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
}

func installTCPDialHook(t *testing.T, gates ...*destGate) {
	t.Helper()
	prev := testHookTCPDial
	testHookTCPDial = func(addr string, err error) {
		for _, g := range gates {
			if g.addr == addr {
				g.onDial(err)
			}
		}
	}
	t.Cleanup(func() { testHookTCPDial = prev })
}

func TestLeftRightRetryPoliciesIsolatedThroughForkedDialing(t *testing.T) {
	t.Run("connectFork", func(t *testing.T) {
		t.Run("exhaust", func(t *testing.T) {
			leftAddr, rightAddr := reservedTCP4Addr(t), reservedTCP4Addr(t)
			leftGate := newDestGate(leftAddr, 0)
			rightGate := newDestGate(rightAddr, 0)
			installTCPDialHook(t, leftGate, rightGate)
			t.Cleanup(leftGate.close)
			t.Cleanup(rightGate.close)
			g := retrySession()
			left := prepareChannel(t, fmt.Sprintf("TCP4:%s,fork,retry=1,interval=0,max-children=1,connect-timeout=1", leftAddr))
			right := prepareChannel(t, fmt.Sprintf("TCP4:%s,retry=3,interval=0,connect-timeout=1", rightAddr))
			requireRetryAttempts(t, left, 2)
			requireRetryAttempts(t, right, 4)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			lo, err := OpenPreparedChannel(ctx, left, ModeRDWR, g)
			if err != nil {
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			go func() {
				finished <- RunOpenedPrepared(ctx, lo, right, g)
			}()
			if err := waitErr(t, finished, 2*time.Second, "left retry=1 exhaust"); err == nil {
				t.Fatal("left retry=1 succeeded")
			}
			if got := leftGate.loadDials(); got != 2 {
				t.Fatalf("left DialTCPAll=%d want 2", got)
			}
			if got := rightGate.loadDials(); got != 0 {
				t.Fatalf("right DialTCPAll=%d want 0", got)
			}

			leftGate2 := newDestGate(reservedTCP4Addr(t), 0)
			rightGate2 := newDestGate(reservedTCP4Addr(t), 0)
			installTCPDialHook(t, leftGate2, rightGate2)
			t.Cleanup(leftGate2.close)
			t.Cleanup(rightGate2.close)
			leftGate2.startListen()
			g2 := retrySession()
			left2 := prepareChannel(t, fmt.Sprintf("TCP4:%s,fork,retry=1,interval=0,max-children=1,connect-timeout=1", leftGate2.addr))
			right2 := prepareChannel(t, fmt.Sprintf("TCP4:%s,retry=3,interval=0,connect-timeout=1", rightGate2.addr))
			requireRetryAttempts(t, left2, 2)
			requireRetryAttempts(t, right2, 4)
			ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel2()
			lo2, err := OpenPreparedChannel(ctx2, left2, ModeRDWR, g2)
			if err != nil {
				t.Fatal(err)
			}
			finished2 := make(chan error, 1)
			go func() {
				finished2 <- RunOpenedPrepared(ctx2, lo2, right2, g2)
			}()
			_ = waitConn(t, ctx2, leftGate2.accepted, "left production TCP")
			rightGate2.waitDials(t, ctx2, 4, "right retry=3 exhaust")
			cancel2()
			_ = waitErr(t, finished2, 2*time.Second, "right exhaust run")
			if got := leftGate2.loadDials(); got != 1 {
				t.Fatalf("left DialTCPAll=%d want 1", got)
			}
			if got := rightGate2.loadDials(); got != 4 {
				t.Fatalf("right DialTCPAll=%d want 4", got)
			}
			if leftGate2.startErr != nil {
				t.Fatal(leftGate2.startErr)
			}
		})

		t.Run("handoff", func(t *testing.T) {
			leftGate := newDestGate(reservedTCP4Addr(t), 0)
			rightGate := newDestGate(reservedTCP4Addr(t), 0)
			installTCPDialHook(t, leftGate, rightGate)
			t.Cleanup(leftGate.close)
			t.Cleanup(rightGate.close)
			leftGate.startListen()
			rightGate.startListen()
			g := retrySession()
			left := prepareChannel(t, fmt.Sprintf("TCP4:%s,fork,retry=1,interval=0,max-children=1,connect-timeout=1", leftGate.addr))
			right := prepareChannel(t, fmt.Sprintf("TCP4:%s,retry=3,interval=0,connect-timeout=1", rightGate.addr))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			lo, err := OpenPreparedChannel(ctx, left, ModeRDWR, g)
			if err != nil {
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			go func() {
				finished <- RunOpenedPrepared(ctx, lo, right, g)
			}()
			leftConn := waitConn(t, ctx, leftGate.accepted, "left production TCP")
			rightConn := waitConn(t, ctx, rightGate.accepted, "right production TCP")
			writeRead(t, leftConn, rightConn, []byte("connect-fork-handoff"))
			cancel()
			_ = waitErr(t, finished, 2*time.Second, "connect-fork handoff")
		})
	})

	t.Run("listenFork", func(t *testing.T) {
		t.Run("exhaust", func(t *testing.T) {
			rightGate := newDestGate(reservedTCP4Addr(t), 0)
			installTCPDialHook(t, rightGate)
			t.Cleanup(rightGate.close)
			left := prepareChannel(t, "TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1,retry=1,max-children=1")
			requireRetryAttempts(t, left, 2)
			right := prepareChannel(t, fmt.Sprintf("TCP4:%s,retry=3,interval=0,connect-timeout=1", rightGate.addr))
			requireRetryAttempts(t, right, 4)
			g := retrySession()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			lo, err := OpenPreparedChannel(ctx, left, ModeRDWR, g)
			if err != nil {
				t.Fatal(err)
			}
			if lo.Listener() == nil {
				t.Fatal("production listen opener did not return a listener")
			}
			finished := make(chan error, 1)
			go func() {
				finished <- RunOpenedPrepared(ctx, lo, right, g)
			}()
			client, err := net.Dial("tcp4", lo.Listener().Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			rightGate.waitDials(t, ctx, 4, "deferred right retry=3 exhaust")
			cancel()
			_ = waitErr(t, finished, 2*time.Second, "listen-fork exhaust")
			if got := rightGate.loadDials(); got != 4 {
				t.Fatalf("right DialTCPAll=%d want 4", got)
			}
		})

		t.Run("handoff", func(t *testing.T) {
			rightGate := newDestGate(reservedTCP4Addr(t), 0)
			installTCPDialHook(t, rightGate)
			t.Cleanup(rightGate.close)
			rightGate.startListen()
			left := prepareChannel(t, "TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1,retry=1,max-children=1")
			requireRetryAttempts(t, left, 2)
			right := prepareChannel(t, fmt.Sprintf("TCP4:%s,retry=3,interval=0,connect-timeout=1", rightGate.addr))
			g := retrySession()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			lo, err := OpenPreparedChannel(ctx, left, ModeRDWR, g)
			if err != nil {
				t.Fatal(err)
			}
			if lo.Listener() == nil {
				t.Fatal("production listen opener did not return a listener")
			}
			finished := make(chan error, 1)
			go func() {
				finished <- RunOpenedPrepared(ctx, lo, right, g)
			}()
			client, err := net.Dial("tcp4", lo.Listener().Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			rightConn := waitConn(t, ctx, rightGate.accepted, "deferred right production TCP")
			writeRead(t, client, rightConn, []byte("listen-fork-handoff"))
			cancel()
			_ = waitErr(t, finished, 2*time.Second, "listen-fork handoff")
		})
	})
}

func TestCancelDuringRetryStopsAttemptsAndWorkers(t *testing.T) {
	gate := newDestGate(reservedTCP4Addr(t), 0)
	installTCPDialHook(t, gate)
	t.Cleanup(gate.close)
	g := retrySession()
	ch := prepareChannel(t, fmt.Sprintf("TCP4:%s,forever,interval=1h,connect-timeout=1", gate.addr))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var live atomic.Int64
	finished := make(chan error, 1)
	go func() {
		live.Add(1)
		_, err := OpenPreparedChannel(ctx, ch, ModeRDWR, g)
		live.Add(-1)
		finished <- err
	}()
	gate.waitDials(t, ctx, 1, "failed production connect")
	if got := gate.loadDials(); got != 1 {
		t.Fatalf("dials before cancel=%d want 1", got)
	}
	cancel()
	err := waitErr(t, finished, 2*time.Second, "canceled TCP open")
	if err == nil {
		t.Fatal("canceled open succeeded")
	}
	if got := gate.loadDials(); got != 1 {
		t.Fatalf("dials after cancel=%d want 1", got)
	}
	if got := live.Load(); got != 0 {
		t.Fatalf("orphaned worker live=%d", got)
	}
}
