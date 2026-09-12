package xio

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
)

func retrySessionWithLog(w io.Writer) *Global {
	lg := logx.New()
	lg.SetOutput(w)
	lg.SetLevel(logx.Notice)
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
				sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
	return lc.Listen(context.Background(), "tcp4", addr)
}

func waitSignal(t *testing.T, ctx context.Context, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-ctx.Done():
		t.Fatalf("waiting for %s: %v", what, ctx.Err())
	}
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

func lineHasAddr(line, addr string) bool {
	i := strings.Index(line, addr)
	if i < 0 {
		return false
	}
	after := i + len(addr)
	if after < len(line) {
		c := line[after]
		if c == '.' || c >= '0' && c <= '9' {
			return false
		}
	}
	return true
}

// destGate is a closed TCP4 port that starts listening after startAfter
// production retry notices for that address. openings counts DialTCPAll
// "opening connection" lines from the production opener.
type destGate struct {
	addr       string
	startAfter int64
	openings   atomic.Int64
	retries    atomic.Int64
	startOnce  sync.Once
	mu         sync.Mutex
	ln         net.Listener
	accepted   chan net.Conn
	retried    chan struct{}
	startErr   error
	closed     atomic.Bool
}

func newDestGate(addr string, startAfter uint64) *destGate {
	return &destGate{
		addr:       addr,
		startAfter: int64(startAfter),
		accepted:   make(chan net.Conn, 1),
		retried:    make(chan struct{}, 8),
	}
}

func (g *destGate) observe(line string) {
	if !lineHasAddr(line, g.addr) {
		return
	}
	if strings.Contains(line, "opening connection to AF=") {
		g.openings.Add(1)
	}
	if !strings.Contains(line, "; retrying in ") {
		return
	}
	n := g.retries.Add(1)
	select {
	case g.retried <- struct{}{}:
	default:
	}
	if g.startAfter > 0 && n == g.startAfter {
		g.startListen()
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

type retryFanout struct {
	gates []*destGate
}

func (f *retryFanout) Write(p []byte) (int, error) {
	line := string(p)
	for _, g := range f.gates {
		g.observe(line)
	}
	return len(p), nil
}

func TestLeftRightRetryPoliciesIsolatedThroughForkedDialing(t *testing.T) {
	t.Run("connectFork", func(t *testing.T) {
		leftAddr, rightAddr := reservedTCP4Addr(t), reservedTCP4Addr(t)
		leftGate := newDestGate(leftAddr, 1)
		rightGate := newDestGate(rightAddr, 2)
		g := retrySessionWithLog(&retryFanout{gates: []*destGate{leftGate, rightGate}})
		t.Cleanup(leftGate.close)
		t.Cleanup(rightGate.close)

		left := prepareChannel(t, fmt.Sprintf("TCP4:%s,fork,retry=1,interval=0,max-children=1,connect-timeout=1", leftAddr))
		right := prepareChannel(t, fmt.Sprintf("TCP4:%s,retry=3,interval=0,connect-timeout=1", rightAddr))
		if left.Single.Config.Common.Retry.Policy().MaxAttempts != 2 {
			t.Fatalf("left policy=%+v", left.Single.Config.Common.Retry.Policy())
		}
		if right.Single.Config.Common.Retry.Policy().MaxAttempts != 4 {
			t.Fatalf("right policy=%+v", right.Single.Config.Common.Retry.Policy())
		}

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
		if got := leftGate.openings.Load(); got < 2 {
			t.Fatalf("left DialTCPAll openings=%d want >= 2", got)
		}
		if got := rightGate.openings.Load(); got < 3 {
			t.Fatalf("right DialTCPAll openings=%d want >= 3", got)
		}
		if leftGate.startErr != nil {
			t.Fatal(leftGate.startErr)
		}
		if rightGate.startErr != nil {
			t.Fatal(rightGate.startErr)
		}
		cancel()
		_ = waitErr(t, finished, 2*time.Second, "connect-fork run")
	})

	t.Run("listenFork", func(t *testing.T) {
		rightAddr := reservedTCP4Addr(t)
		left := prepareChannel(t, "TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1,retry=1,max-children=1")
		leftPolicy := left.Single.Config.Common.Retry.Policy()
		if leftPolicy.MaxAttempts < 2 {
			t.Fatalf("left listen retry policy=%+v", leftPolicy)
		}
		rightGate := newDestGate(rightAddr, leftPolicy.MaxAttempts)
		right := prepareChannel(t, fmt.Sprintf("TCP4:%s,retry=3,interval=0,connect-timeout=1", rightAddr))
		g := retrySessionWithLog(&retryFanout{gates: []*destGate{rightGate}})
		t.Cleanup(rightGate.close)

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
		wantOpenings := int64(leftPolicy.MaxAttempts) + 1
		if got := rightGate.openings.Load(); got < wantOpenings {
			t.Fatalf("right DialTCPAll openings=%d want >= %d (left policy MaxAttempts=%d)", got, wantOpenings, leftPolicy.MaxAttempts)
		}
		if rightGate.startErr != nil {
			t.Fatal(rightGate.startErr)
		}
		cancel()
		_ = waitErr(t, finished, 2*time.Second, "listen-fork run")
	})
}

func TestCancelDuringRetryStopsAttemptsAndWorkers(t *testing.T) {
	addr := reservedTCP4Addr(t)
	gate := newDestGate(addr, 0)
	g := retrySessionWithLog(&retryFanout{gates: []*destGate{gate}})
	t.Cleanup(gate.close)
	ch := prepareChannel(t, fmt.Sprintf("TCP4:%s,forever,interval=1h,connect-timeout=1", addr))

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
	waitSignal(t, ctx, gate.retried, "nonzero retry delay")
	if got := gate.openings.Load(); got != 1 {
		t.Fatalf("openings before cancel=%d want 1", got)
	}
	cancel()
	err := waitErr(t, finished, 2*time.Second, "canceled TCP open")
	if err == nil {
		t.Fatal("canceled open succeeded")
	}
	if got := gate.openings.Load(); got != 1 {
		t.Fatalf("openings after cancel=%d want 1", got)
	}
	if got := live.Load(); got != 0 {
		t.Fatalf("orphaned worker live=%d", got)
	}
}
