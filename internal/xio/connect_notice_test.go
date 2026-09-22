package xio_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
)

var noticeVisibility = []struct {
	name    string
	level   logx.Level
	visible bool
}{
	{"visible", logx.Debug, true},
	{"hidden below notice", logx.Warning, false},
}

func TestTCPConnectSuccessLoggedAtNotice(t *testing.T) {
	for _, tc := range noticeVisibility {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testCtx(t)
			ln := listenLoopback(t)
			peerCh := acceptRemote(t, ln)
			g, buf := loggedSession(tc.level)
			spec := "TCP4:" + ln.Addr().String() + ",connect-timeout=2"
			o, err := xio.OpenChannel(ctx, mustParse(t, spec), xio.ModeRDWR, g)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = o.Close() })
			assertEndpointLevel(t, buf.String(), waitAddr(t, ctx, peerCh), tc.visible)
		})
	}
}

func TestTCPAcceptLoggedAtNotice(t *testing.T) {
	for _, tc := range noticeVisibility {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testCtx(t)
			port := reserveLoopbackPort(t)
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			peerCh := make(chan string, 1)
			go func() {
				var conn net.Conn
				err := testutil.Until(ctx, func() (bool, error) {
					c, dialErr := net.Dial("tcp4", addr)
					if dialErr != nil {
						return false, nil
					}
					conn = c
					return true, nil
				})
				if err != nil || conn == nil {
					return
				}
				peerCh <- conn.LocalAddr().String()
				_ = conn.Close()
			}()

			g, buf := loggedSession(tc.level)
			spec := fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,bind=127.0.0.1", port)
			o, err := xio.OpenChannel(ctx, mustParse(t, spec), xio.ModeRDWR, g)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = o.Close() })
			assertEndpointLevel(t, buf.String(), waitAddr(t, ctx, peerCh), tc.visible)
		})
	}
}

func TestForkAcceptLoggedAtNotice(t *testing.T) {
	ctx := testCtx(t)
	side := listenLoopback(t)
	g, buf := loggedSession(logx.Debug)
	lo, err := xio.OpenChannel(ctx, mustParse(t, "TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1"), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	if lo.Listener() == nil {
		_ = lo.Close()
		t.Fatal("listen did not return a listener")
	}
	sideReady := acceptAndClose(side)
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		right := fmt.Sprintf("TCP4:%s,connect-timeout=2", side.Addr())
		_ = xio.RunOpened(runCtx, lo, mustParse(t, right), g)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	var client net.Conn
	err = testutil.Until(ctx, func() (bool, error) {
		c, dialErr := net.Dial("tcp4", lo.Listener().Addr().String())
		if dialErr != nil {
			return false, nil
		}
		client = c
		return true, nil
	})
	if err != nil || client == nil {
		t.Fatalf("dial listen: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	waitReady(t, ctx, sideReady)
	assertEndpointLevel(t, buf.String(), client.LocalAddr().String(), true)
}

func TestConnectForkSuccessLoggedAtNotice(t *testing.T) {
	ctx := testCtx(t)
	target := listenLoopback(t)
	side := listenLoopback(t)
	g, buf := loggedSession(logx.Debug)

	left := fmt.Sprintf("TCP4:%s,fork,interval=30,connect-timeout=2", target.Addr())
	lo, err := xio.OpenChannel(ctx, mustParse(t, left), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	peerCh := acceptRemote(t, target)
	sideReady := acceptAndClose(side)

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		right := fmt.Sprintf("TCP4:%s,connect-timeout=2", side.Addr())
		_ = xio.RunOpened(runCtx, lo, mustParse(t, right), g)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	waitReady(t, ctx, sideReady)
	assertEndpointLevel(t, buf.String(), waitAddr(t, ctx, peerCh), true)
}

func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func reserveLoopbackPort(t *testing.T) int {
	t.Helper()
	ln := listenLoopback(t)
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func acceptRemote(t *testing.T, ln net.Listener) <-chan string {
	t.Helper()
	ch := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		ch <- c.RemoteAddr().String()
		_, _ = io.Copy(io.Discard, c)
		_ = c.Close()
	}()
	return ch
}

func acceptAndClose(ln net.Listener) <-chan struct{} {
	ch := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
		ch <- struct{}{}
	}()
	return ch
}

func waitAddr(t *testing.T, ctx context.Context, ch <-chan string) string {
	t.Helper()
	select {
	case addr := <-ch:
		return addr
	case <-ctx.Done():
		t.Fatal("timed out waiting for the peer address")
		return ""
	}
}

func waitReady(t *testing.T, ctx context.Context, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-ctx.Done():
		t.Fatal("timed out waiting for the child to open its right address")
	}
}

func loggedSession(level logx.Level) (*xio.Global, *lockedBuf) {
	var buf lockedBuf
	lg := logx.New()
	lg.SetOutput(&buf)
	lg.SetLevel(level)
	return xio.NewSession(xio.Options{BlockSize: 8192, Linger: 200 * time.Millisecond}, lg), &buf
}

var diagnosticSeverity = regexp.MustCompile(`\[[0-9]+\] ([FEDWNI]) `)

func assertEndpointLevel(t *testing.T, text, endpoint string, visible bool) {
	t.Helper()
	levels := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, endpoint) {
			continue
		}
		m := diagnosticSeverity.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		levels[m[1]] = true
	}
	if visible {
		if !levels["N"] || levels["I"] {
			t.Fatalf("endpoint %s levels=%v\n%s", endpoint, levels, text)
		}
		return
	}
	if len(levels) != 0 {
		t.Fatalf("endpoint %s visible at %v\n%s", endpoint, levels, text)
	}
}
