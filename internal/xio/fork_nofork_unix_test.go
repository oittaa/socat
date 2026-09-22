//go:build linux || darwin

package xio_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

// lockedLog is a concurrent log sink. Fork children clone the logger and
// write from their own goroutines.
type lockedLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestListenForkSystemNoForkWritesToEachClient(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	srv := startListenRight(t, ctx, g,
		"TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1",
		"SYSTEM:echo fork-nofork,nofork")
	port := tcpPort(t, srv)
	const want = "fork-nofork\n"
	for i := 0; i < 2; i++ {
		cli := openClient(t, ctx, g, "TCP4:127.0.0.1:"+port)
		if got := string(readFull(t, streamOf(t, cli), len(want))); got != want {
			t.Fatalf("client %d got %q", i, got)
		}
	}
}

func TestSystemNoForkOnLeftOfListenFork(t *testing.T) {
	ctx := testCtx(t)
	port := reserveTCPPort(t)
	left := mustParse(t, "SYSTEM:echo left-nofork,nofork")
	right := mustParse(t, fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,fork,bind=127.0.0.1", port))
	go func() {
		_ = xio.Run(ctx, left, right, testGlobal())
	}()
	const want = "left-nofork\n"
	for i := 0; i < 2; i++ {
		cli := openClient(t, ctx, testGlobal(), fmt.Sprintf("TCP4:127.0.0.1:%d", port))
		if got := string(readFull(t, streamOf(t, cli), len(want))); got != want {
			t.Fatalf("client %d got %q", i, got)
		}
	}
}

func TestConnectForkSystemNoForkWritesToPeer(t *testing.T) {
	ctx := testCtx(t)
	ln := listenTCP(t)
	const want = "connect-nofork\n"
	got := make(chan string, 1)
	go readAcceptedN(ln, len(want), got)
	left := mustParse(t, fmt.Sprintf("TCP4:127.0.0.1:%d,fork,interval=1", ln.Addr().(*net.TCPAddr).Port))
	right := mustParse(t, "SYSTEM:echo connect-nofork,nofork")
	go func() {
		_ = xio.Run(ctx, left, right, testGlobal())
	}()
	assertChan(t, ctx, got, want)
}

func TestSystemNoForkOnLeftOfConnectFork(t *testing.T) {
	ctx := testCtx(t)
	ln := listenTCP(t)
	const want = "left-connect\n"
	got := make(chan string, 1)
	go readAcceptedN(ln, len(want), got)
	left := mustParse(t, "EXEC:/bin/echo left-connect,nofork")
	right := mustParse(t, fmt.Sprintf("TCP4:127.0.0.1:%d,fork,interval=1", ln.Addr().(*net.TCPAddr).Port))
	go func() {
		_ = xio.Run(ctx, left, right, testGlobal())
	}()
	assertChan(t, ctx, got, want)
}

func TestConnectForkOpenErrorLoggedAtError(t *testing.T) {
	ctx := testCtx(t)
	ln := listenTCP(t)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	var sink lockedLog
	log := logx.New()
	log.SetOutput(&sink)
	g := xio.NewSession(xio.Options{BlockSize: 8192}, log)
	path := t.TempDir() + "/missing-fork-open"
	left := mustParse(t, fmt.Sprintf("TCP4:127.0.0.1:%d,fork,interval=0.2", ln.Addr().(*net.TCPAddr).Port))
	right := mustParse(t, "OPEN:"+path)
	go func() {
		_ = xio.Run(ctx, left, right, g)
	}()
	wait, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	err := testutil.Until(wait, func() (bool, error) {
		return strings.Contains(sink.String(), `open("`+path+`"`), nil
	})
	if err != nil {
		t.Fatalf("open error not logged at Error: %q", sink.String())
	}
}

func TestRecvfromForkSystemNoForkReplies(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	srv := startListenRight(t, ctx, g,
		"UDP4-RECVFROM:0,fork,bind=127.0.0.1",
		"SYSTEM:echo recv-nofork,nofork")
	cli := openClient(t, ctx, g, "UDP4:127.0.0.1:"+tcpPort(t, srv))
	mustWrite(t, streamOf(t, cli), []byte("x"))
	const want = "recv-nofork\n"
	if got := string(readFull(t, streamOf(t, cli), len(want))); got != want {
		t.Fatalf("got %q", got)
	}
}

func TestSystemNoForkWithoutForkStillWrites(t *testing.T) {
	ctx := testCtx(t)
	port := reserveTCPPort(t)
	left := mustParse(t, fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,bind=127.0.0.1", port))
	right := mustParse(t, "SYSTEM:echo once-nofork,nofork")
	go func() {
		_ = xio.Run(ctx, left, right, testGlobal())
	}()
	const want = "once-nofork\n"
	cli := openClient(t, ctx, testGlobal(), fmt.Sprintf("TCP4:127.0.0.1:%d", port))
	if got := string(readFull(t, streamOf(t, cli), len(want))); got != want {
		t.Fatalf("got %q", got)
	}
}

func reserveTCPPort(t *testing.T) int {
	t.Helper()
	ln := listenTCP(t)
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func listenTCP(t *testing.T) *net.TCPListener {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	tcpLn, ok := ln.(*net.TCPListener)
	if !ok {
		t.Fatalf("listener %T", ln)
	}
	return tcpLn
}

func readAcceptedN(ln *net.TCPListener, n int, got chan<- string) {
	c, err := ln.Accept()
	if err != nil {
		got <- ""
		return
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, n)
	_, err = io.ReadFull(c, buf)
	if err != nil {
		got <- ""
		return
	}
	got <- string(buf)
}

func assertChan(t *testing.T, ctx context.Context, got <-chan string, want string) {
	t.Helper()
	select {
	case s := <-got:
		if s != want {
			t.Fatalf("got %q want %q", s, want)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
