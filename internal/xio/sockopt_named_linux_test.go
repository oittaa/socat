//go:build linux

package xio

import (
	"context"
	"errors"
	"net"
	"strconv"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func fdTCPSockoptInt(t *testing.T, fd, opt int) int {
	t.Helper()
	v, err := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, opt)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func connTCPSockoptInt(t *testing.T, conn syscall.Conn, opt int) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		v, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, opt)
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}

func listenerTCPSockoptInt(t *testing.T, ln net.Listener, opt int) int {
	t.Helper()
	sc, ok := ln.(syscall.Conn)
	if !ok {
		t.Fatalf("listener type %T is not syscall.Conn", ln)
	}
	return connTCPSockoptInt(t, sc, opt)
}

func TestApplySocketOptionsNamedTCPLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,tcp-cork,tcp-maxseg=512,tcp-quickack=0,tcp-syncnt=4,linger2=10,window-clamp=32768,tcp-defer-accept=30")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, spec); err != nil {
		t.Fatal(err)
	}
	if got := fdTCPSockoptInt(t, fd, unix.TCP_CORK); got != 1 {
		t.Fatalf("TCP_CORK=%d want 1", got)
	}
	if got := fdTCPSockoptInt(t, fd, unix.TCP_MAXSEG); got != 512 {
		t.Fatalf("TCP_MAXSEG=%d want 512", got)
	}
	if got := fdTCPSockoptInt(t, fd, unix.TCP_QUICKACK); got != 0 {
		t.Fatalf("TCP_QUICKACK=%d want 0", got)
	}
	if got := fdTCPSockoptInt(t, fd, unix.TCP_SYNCNT); got != 4 {
		t.Fatalf("TCP_SYNCNT=%d want 4", got)
	}
	if got := fdTCPSockoptInt(t, fd, unix.TCP_LINGER2); got != 10 {
		t.Fatalf("TCP_LINGER2=%d want 10", got)
	}
	if got := fdTCPSockoptInt(t, fd, unix.TCP_WINDOW_CLAMP); got != 32768 {
		t.Fatalf("TCP_WINDOW_CLAMP=%d want 32768", got)
	}
	if got := fdTCPSockoptInt(t, fd, unix.TCP_DEFER_ACCEPT); got < 30 {
		t.Fatalf("TCP_DEFER_ACCEPT=%d want >= 30", got)
	}
}

func TestApplySocketOptionsCorkAliasAndClearLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	on, err := parse.ParseSpec("TCP:127.0.0.1:9,cork")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, on); err != nil {
		t.Fatal(err)
	}
	if got := fdTCPSockoptInt(t, fd, unix.TCP_CORK); got != 1 {
		t.Fatalf("cork alias TCP_CORK=%d want 1", got)
	}
	off, err := parse.ParseSpec("TCP:127.0.0.1:9,tcp-cork=0")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, off); err != nil {
		t.Fatal(err)
	}
	if got := fdTCPSockoptInt(t, fd, unix.TCP_CORK); got != 0 {
		t.Fatalf("tcp-cork=0 TCP_CORK=%d want 0", got)
	}
}

func TestApplySocketOptionsRejectsInvalidTCPLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	for _, specText := range []string{
		"TCP:127.0.0.1:9,tcp-maxseg=1",
		"TCP:127.0.0.1:9,tcp-syncnt=128",
		"TCP:127.0.0.1:9,tcp-cork=no",
	} {
		spec, err := parse.ParseSpec(specText)
		if err != nil {
			t.Fatal(err)
		}
		if err := ApplySocketOptions(fd, spec); err == nil {
			t.Fatalf("%s: expected failure", specText)
		}
	}
}

func TestApplySocketOptionsTCPCorkOnUDPLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	spec, err := parse.ParseSpec("UDP:127.0.0.1:9,tcp-cork")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplySocketOptions(fd, spec)
	if err == nil {
		t.Fatal("tcp-cork on UDP must fail, not no-op")
	}
	if !errors.Is(err, unix.ENOPROTOOPT) && !errors.Is(err, unix.EOPNOTSUPP) {
		t.Fatalf("tcp-cork on UDP error=%v want ENOPROTOOPT/EOPNOTSUPP", err)
	}
}

func TestApplySocketOptionsTCPCorkOnSCTPLinux(t *testing.T) {
	// SCTP is SOCK_STREAM+IPPROTO_SCTP. GROUP_IP_TCP is rejected by the CLI;
	// if the option still reaches apply, TCP_* must fail clearly, not no-op.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_SCTP)
	if err != nil {
		t.Skipf("SCTP socket unavailable (%v); CLI still rejects GROUP_IP_TCP on SCTP addresses", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	spec, err := parse.ParseSpec("SCTP:127.0.0.1:9,tcp-cork")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplySocketOptions(fd, spec)
	if err == nil {
		t.Fatal("tcp-cork on SCTP must fail, not no-op")
	}
}

func TestApplySocketOptionsDoesNotApplyMaxsegLateLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	before := fdTCPSockoptInt(t, fd, unix.TCP_MAXSEG)
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,tcp-maxseg-late=512")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, spec); err != nil {
		t.Fatal(err)
	}
	after := fdTCPSockoptInt(t, fd, unix.TCP_MAXSEG)
	if after == 512 && before != 512 {
		t.Fatalf("tcp-maxseg-late applied at PASTSOCKET: TCP_MAXSEG %d → %d", before, after)
	}
}

func TestListenControlAppliesMaxsegNotLateLinux(t *testing.T) {
	past, err := parse.ParseSpec("TCP4-LISTEN:0,tcp-maxseg=512")
	if err != nil {
		t.Fatal(err)
	}
	lc := NewTCPListenConfig(past)
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if got := listenerTCPSockoptInt(t, ln, unix.TCP_MAXSEG); got != 512 {
		t.Fatalf("listener TCP_MAXSEG=%d want 512 after tcp-maxseg", got)
	}

	late, err := parse.ParseSpec("TCP4-LISTEN:0,tcp-maxseg-late=512")
	if err != nil {
		t.Fatal(err)
	}
	var n int
	restore := SetSockoptTestHook(func(c SockoptCall) {
		if c.Level == unix.IPPROTO_TCP && c.Opt == unix.TCP_MAXSEG {
			n++
		}
	})
	t.Cleanup(restore)
	lc = NewTCPListenConfig(late)
	ln2, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln2.Close() })
	if n != 0 {
		t.Fatalf("tcp-maxseg-late applied at PASTSOCKET (%d TCP_MAXSEG setsockopt)", n)
	}
}

func TestListenControlAppliesDeferAcceptLinux(t *testing.T) {
	spec, err := parse.ParseSpec("TCP4-LISTEN:0,defer-accept=30")
	if err != nil {
		t.Fatal(err)
	}
	lc := NewTCPListenConfig(spec)
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if got := listenerTCPSockoptInt(t, ln, unix.TCP_DEFER_ACCEPT); got < 30 {
		t.Fatalf("listener TCP_DEFER_ACCEPT=%d want >= 30", got)
	}
}

func TestDialControlAppliesSyncntLinux(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	spec, err := parse.ParseSpec("TCP4:127.0.0.1:9,tcp-syncnt=4")
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: DialControl(spec, "tcp4", nil)}
	d.SetMultipathTCP(false)
	cli, err := d.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	if got := connTCPSockoptInt(t, cli.(syscall.Conn), unix.TCP_SYNCNT); got != 4 {
		t.Fatalf("TCP_SYNCNT=%d want 4 after DialControl", got)
	}
}

func TestApplyTCPConnOptsMaxsegLateLinux(t *testing.T) {
	cli, _ := tcpPair(t)
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,tcp-maxseg-late=1")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyTCPConnOpts(spec, cli)
	if err == nil {
		t.Fatal("tcp-maxseg-late=1 must fail (kernel TCP_MAXSEG=1), not no-op")
	}

	okSpec, err := parse.ParseSpec("TCP:127.0.0.1:9,mss-late=512")
	if err != nil {
		t.Fatal(err)
	}
	var saw bool
	restore := SetSockoptTestHook(func(c SockoptCall) {
		if c.Level == unix.IPPROTO_TCP && c.Opt == unix.TCP_MAXSEG && c.IntValue == 512 {
			saw = true
		}
	})
	defer restore()
	if err := ApplyTCPConnOpts(okSpec, cli); err != nil {
		t.Fatal(err)
	}
	if !saw {
		t.Fatal("tcp-maxseg-late=512 did not call setsockopt TCP_MAXSEG")
	}
}

func TestDialTCPAllAppliesPastSocketCorkOnceLinux(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	spec, err := parse.ParseSpec("TCP4:127.0.0.1:9,tcp-cork")
	if err != nil {
		t.Fatal(err)
	}
	var n int
	restore := SetSockoptTestHook(func(c SockoptCall) {
		if c.Level == unix.IPPROTO_TCP && c.Opt == unix.TCP_CORK {
			n++
		}
	})
	defer restore()
	port := ln.Addr().(*net.TCPAddr).Port
	c, err := DialTCPAll(context.Background(), "tcp4", "127.0.0.1", strconv.Itoa(port), spec, nil, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if n != 1 {
		t.Fatalf("TCP_CORK setsockopt count=%d want 1 (PASTSOCKET only, not CONNECTED twice)", n)
	}
	if got := connTCPSockoptInt(t, c.(syscall.Conn), unix.TCP_CORK); got != 1 {
		t.Fatalf("TCP_CORK=%d want 1 after DialTCPAll", got)
	}
}

func TestApplyTCPConnOptsMaxsegLateThroughNetConnUnwrapLinux(t *testing.T) {
	cli, _ := tcpPair(t)
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,tcp-maxseg-late=1")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyTCPConnOpts(spec, netConnUnwrapper{Conn: cli})
	if err == nil {
		t.Fatal("tcp-maxseg-late through NetConn unwrap must reach the kernel")
	}
}
