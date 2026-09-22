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
		if got := string(readAll(t, streamOf(t, cli))); got != want {
			t.Fatalf("client %d got %q", i, got)
		}
	}
}

func TestNoForkRejectedOnFirstAddress(t *testing.T) {
	ctx := testCtx(t)
	cases := []struct {
		name  string
		left  string
		right string
	}{
		{name: "listen-fork", left: "SYSTEM:echo left-nofork,nofork", right: "TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1"},
		{name: "listen", left: "SYSTEM:echo left-nofork,nofork", right: "TCP4-LISTEN:0,reuseaddr,bind=127.0.0.1"},
		{name: "connect-fork", left: "EXEC:/bin/echo left-connect,nofork", right: "TCP4:127.0.0.1:1,fork,interval=1"},
		{name: "connect", left: "EXEC:/bin/echo left-connect,nofork", right: "TCP4:127.0.0.1:1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := xio.Run(ctx, mustParse(t, tc.left), mustParse(t, tc.right), testGlobal())
			if err == nil || !strings.Contains(err.Error(), "option nofork is not allowed here") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestOpenedNoForkOnLeftRejected(t *testing.T) {
	ctx := testCtx(t)
	left, err := xio.OpenChannel(ctx, mustParse(t, "SYSTEM:echo hi,nofork"), xio.ModeRDWR, testGlobal())
	if err != nil {
		t.Fatal(err)
	}
	err = xio.RunOpened(ctx, left, mustParse(t, "PIPE"), testGlobal())
	if err == nil || !strings.Contains(err.Error(), "option nofork is not allowed here") {
		t.Fatalf("got %v", err)
	}
}

func TestConnectForkSystemNoForkWritesToPeer(t *testing.T) {
	ctx := testCtx(t)
	ln := listenTCP(t)
	const want = "connect-nofork\n"
	got := make(chan string, 1)
	go readAcceptedAll(ln, got)
	left := mustParse(t, fmt.Sprintf("TCP4:127.0.0.1:%d,fork,interval=1", ln.Addr().(*net.TCPAddr).Port))
	right := mustParse(t, "SYSTEM:echo connect-nofork,nofork")
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
	log.SetLevel(logx.Debug)
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
		for _, line := range strings.Split(sink.String(), "\n") {
			if strings.Contains(line, " E ") && strings.Contains(line, `open("`+path+`"`) {
				return true, nil
			}
		}
		return false, nil
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
	cli := openClient(t, ctx, g, "UDP4:127.0.0.1:"+fmt.Sprintf("%d", listenerPort(t, srv)))
	mustWrite(t, streamOf(t, cli), []byte("x"))
	const want = "recv-nofork\n"
	if got := readDatagram(t, streamOf(t, cli)); got != want {
		t.Fatalf("got %q", got)
	}
}

func TestRecvfromForkMaxChildrenNoForkServesSequentialPeers(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	srv := startListenRight(t, ctx, g,
		"UDP4-RECVFROM:0,fork,max-children=1,bind=127.0.0.1",
		"SYSTEM:echo recv-nofork,nofork")
	port := fmt.Sprintf("%d", listenerPort(t, srv))
	const want = "recv-nofork\n"
	for i := 0; i < 2; i++ {
		cli := openClient(t, ctx, g, "UDP4:127.0.0.1:"+port)
		mustWrite(t, streamOf(t, cli), []byte("x"))
		if got := readDatagram(t, streamOf(t, cli)); got != want {
			t.Fatalf("peer %d got %q", i, got)
		}
		_ = cli.Close()
	}
}

func TestListenForkMissingExecNoForkEOF(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	srv := startListenRight(t, ctx, g,
		"TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1",
		"EXEC:/no/such/socat-nofork-missing,nofork")
	cli := openClient(t, ctx, g, "TCP4:127.0.0.1:"+tcpPort(t, srv))
	if got := readAll(t, streamOf(t, cli)); len(got) != 0 {
		t.Fatalf("got %q", got)
	}
}

func TestSystemNoForkWithoutForkStillWrites(t *testing.T) {
	ctx := testCtx(t)
	var sink lockedLog
	log := logx.New()
	log.SetLevel(logx.Notice)
	log.SetOutput(&sink)
	g := xio.NewSession(xio.Options{BlockSize: 8192}, log)
	go func() {
		_ = xio.Run(ctx,
			mustParse(t, "TCP4-LISTEN:0,reuseaddr,bind=127.0.0.1"),
			mustParse(t, "SYSTEM:echo once-nofork,nofork"),
			g)
	}()
	port := waitListenPort(t, ctx, &sink)
	const want = "once-nofork\n"
	cli := openClient(t, ctx, testGlobal(), "TCP4:127.0.0.1:"+port)
	if got := string(readAll(t, streamOf(t, cli))); got != want {
		t.Fatalf("got %q", got)
	}
}

func waitListenPort(t *testing.T, ctx context.Context, sink *lockedLog) string {
	t.Helper()
	var port string
	err := testutil.Until(ctx, func() (bool, error) {
		const mark = "listening on "
		text := sink.String()
		i := strings.Index(text, mark)
		if i < 0 {
			return false, nil
		}
		rest := text[i+len(mark):]
		end := strings.IndexAny(rest, " \n")
		if end < 0 {
			return false, nil
		}
		_, p, splitErr := net.SplitHostPort(rest[:end])
		if splitErr != nil {
			return false, nil
		}
		port = p
		return true, nil
	})
	if err != nil {
		t.Fatalf("listening port: %v log %q", err, sink.String())
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

func readAcceptedAll(ln *net.TCPListener, got chan<- string) {
	c, err := ln.Accept()
	if err != nil {
		got <- ""
		return
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	b, err := io.ReadAll(c)
	if err != nil {
		got <- ""
		return
	}
	got <- string(b)
}

func readDatagram(t *testing.T, r io.Reader) string {
	t.Helper()
	setRWDeadline(r, 3*time.Second)
	buf := make([]byte, 256)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:n])
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
