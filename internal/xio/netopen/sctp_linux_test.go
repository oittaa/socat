//go:build linux

package netopen

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

// linux/sctp.h; xio keeps the same constants unexported.
const (
	testSCTPNodelay = 3
	testSCTPMaxseg  = 13
)

func skipIfNoSCTP(t *testing.T) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_SCTP)
	if err != nil {
		t.Skipf("no kernel SCTP: %v", err)
	}
	_ = unix.Close(fd)
}

func TestSCTP4Echo(t *testing.T) {
	skipIfNoSCTP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ln, err := listenSCTP(ctx, "sctp4", "127.0.0.1", "0", parse.Spec{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	ta, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("addr type %T", ln.Addr())
	}
	port := ta.Port
	// FileListener is created lazily on Accept. Create it before dial so a
	// fast client is not lost on a raw listen fd (seen on GitHub runners).
	if dl, ok := ln.(interface{ SetDeadline(time.Time) error }); ok {
		_ = dl.SetDeadline(time.Time{})
	}
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- "accept:" + err.Error()
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		want := "hello-sctp"
		b := make([]byte, len(want))
		if _, err := io.ReadFull(c, b); err != nil {
			got <- "read:" + err.Error()
			return
		}
		got <- string(b)
	}()

	g := &xio.Global{Log: logx.New()}
	c, err := dialSCTPAll(ctx, "sctp4", "127.0.0.1", strconv.Itoa(port), parse.Spec{}, g, 3*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(c, "hello-sctp"); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
		t.Fatal("timeout")
	case s := <-got:
		if s != "hello-sctp" {
			t.Fatalf("got %q", s)
		}
	}
}

func TestSCTPOpenChannelListenTimeout(t *testing.T) {
	skipIfNoSCTP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch, err := parse.ParseChannel("SCTP4-LISTEN:0,reuseaddr,bind=127.0.0.1,accept-timeout=0.05")
	if err != nil {
		t.Fatal(err)
	}
	g := &xio.Global{Log: logx.New()}
	_, err = xio.OpenChannel(ctx, ch, xio.ModeRDWR, g)
	if err != xio.ErrAcceptTimeout {
		t.Fatalf("want accept timeout, got %v", err)
	}
}

func TestSCTPServiceNameHTTP(t *testing.T) {
	n, err := xio.ResolvePortNum("sctp4", "http")
	if err != nil {
		t.Fatal(err)
	}
	if n != 80 {
		t.Fatalf("http=%d", n)
	}
}

func TestSCTPConnectErrTreatsEstablishedEISCONNAsSuccess(t *testing.T) {
	if err := sctpConnectErr(nil, nil); err != nil {
		t.Fatalf("nil connect err: %v", err)
	}
	if err := sctpConnectErr(unix.EISCONN, func() error { return nil }); err != nil {
		t.Fatalf("established EISCONN: %v", err)
	}
	if err := sctpConnectErr(unix.EISCONN, func() error { return unix.EINVAL }); !errors.Is(err, unix.EISCONN) {
		t.Fatalf("unconnected EISCONN: %v", err)
	}
	if err := sctpConnectErr(unix.ECONNREFUSED, nil); err == nil || err.Error() != "Connection refused" {
		t.Fatalf("ECONNREFUSED: %v", err)
	}
}

func connSCTPSockoptInt(t *testing.T, conn syscall.Conn, opt int) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		v, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_SCTP, opt)
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}

func TestSCTPListenDialNamedSockoptsLinux(t *testing.T) {
	skipIfNoSCTP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	listenSpec, err := parse.ParseSpec("SCTP4-LISTEN:0,reuseaddr,sctp-nodelay,sctp-maxseg=1400")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := listenSCTP(ctx, "sctp4", "127.0.0.1", "0", listenSpec)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	rl, ok := ln.(*rawListener)
	if !ok {
		t.Fatalf("listener type %T", ln)
	}
	gotNodelay, err := unix.GetsockoptInt(rl.fd, unix.IPPROTO_SCTP, testSCTPNodelay)
	if err != nil {
		t.Fatal(err)
	}
	if gotNodelay != 1 {
		t.Fatalf("listen SCTP_NODELAY=%d want 1 (PH_PASTSOCKET)", gotNodelay)
	}
	gotMaxseg, err := unix.GetsockoptInt(rl.fd, unix.IPPROTO_SCTP, testSCTPMaxseg)
	if err != nil {
		t.Fatal(err)
	}
	if gotMaxseg != 1400 {
		t.Fatalf("listen SCTP_MAXSEG=%d want 1400 (PH_PASTSOCKET)", gotMaxseg)
	}

	if dl, ok := ln.(interface{ SetDeadline(time.Time) error }); ok {
		_ = dl.SetDeadline(time.Time{})
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()

	ta, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("addr type %T", ln.Addr())
	}
	dialSpec, err := parse.ParseSpec("SCTP4:127.0.0.1:9,sctp-nodelay,sctp-maxseg=1400")
	if err != nil {
		t.Fatal(err)
	}
	g := &xio.Global{Log: logx.New()}
	cli, err := dialSCTPAll(ctx, "sctp4", "127.0.0.1", strconv.Itoa(ta.Port), dialSpec, g, 3*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	sc, ok := cli.(syscall.Conn)
	if !ok {
		t.Fatalf("dial conn type %T is not syscall.Conn", cli)
	}
	if got := connSCTPSockoptInt(t, sc, testSCTPNodelay); got != 1 {
		t.Fatalf("dial SCTP_NODELAY=%d want 1", got)
	}
	if got := connSCTPSockoptInt(t, sc, testSCTPMaxseg); got != 1400 {
		t.Fatalf("dial SCTP_MAXSEG=%d want 1400", got)
	}

	select {
	case <-ctx.Done():
		t.Fatal("accept timeout")
	case acc := <-accepted:
		if acc == nil {
			t.Fatal("accept failed")
		}
		t.Cleanup(func() { _ = acc.Close() })
		asc, ok := acc.(syscall.Conn)
		if !ok {
			t.Logf("accepted conn %T is not syscall.Conn; skip inheritance check", acc)
			return
		}
		got, err := func() (int, error) {
			raw, err := asc.SyscallConn()
			if err != nil {
				return 0, err
			}
			var v int
			var gerr error
			if err := raw.Control(func(fd uintptr) {
				v, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_SCTP, testSCTPNodelay)
			}); err != nil {
				return 0, err
			}
			return v, gerr
		}()
		if err != nil {
			t.Logf("accepted SCTP_NODELAY getsockopt: %v (classic consumes PH_PASTSOCKET on the listen fd)", err)
			return
		}
		if got != 1 {
			t.Logf("accepted SCTP_NODELAY=%d; kernel inheritance is where-applicable (classic does not re-apply after accept)", got)
		}
	}
}
