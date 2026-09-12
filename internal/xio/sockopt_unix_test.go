//go:build linux || darwin

package xio

import (
	"net"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestDecodeRejectsInvalidSocketTimeouts(t *testing.T) {
	for _, value := range []string{"-1", "banana", "NaN", "1e100"} {
		spec, err := parse.ParseSpec("TCP:127.0.0.1:9,rcvtimeo=" + value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeAddress(spec); err == nil {
			t.Errorf("rcvtimeo=%q accepted", value)
		}
	}
}

func unixSockoptInt(t *testing.T, fd, opt int) int {
	t.Helper()
	got, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, opt)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestApplySocketOptionsRejectsNegativeSndbuf(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	spec, err := parse.ParseSpec("UDP:127.0.0.1:9,sndbuf=-1")
	if err != nil {
		t.Fatal(err)
	}
	config, err := decodeAddress(spec)
	if err == nil {
		err = ApplySocketOptions(fd, config)
	}
	if err == nil {
		t.Fatal("expected invalid sndbuf error")
	}
}

type netConnUnwrapper struct {
	net.Conn
}

func (c netConnUnwrapper) NetConn() net.Conn { return c.Conn }

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	cli, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	srv := <-ch
	if srv.err != nil {
		t.Fatal(srv.err)
	}
	t.Cleanup(func() { _ = srv.c.Close() })
	return cli, srv.c.(*net.TCPConn)
}

func tcpSockoptInt(t *testing.T, tc *net.TCPConn, opt int) int {
	t.Helper()
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	_ = raw.Control(func(fd uintptr) {
		v, gerr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, opt)
	})
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}

func TestApplyTCPConnOptsAppliesSndbufLateThroughNetConnUnwrap(t *testing.T) {
	cli, _ := tcpPair(t)
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,sndbuf-late=65536")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTCPConnOpts(mustDecodeAddress(t, spec), netConnUnwrapper{Conn: cli}); err != nil {
		t.Fatal(err)
	}
	if got := tcpSockoptInt(t, cli, unix.SO_SNDBUF); got < 65536 {
		t.Fatalf("SO_SNDBUF=%d want >= 65536 through NetConn() unwrap", got)
	}
}

func udpSockoptInt(t *testing.T, uc *net.UDPConn, opt int) int {
	t.Helper()
	raw, err := uc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	_ = raw.Control(func(fd uintptr) {
		v, gerr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, opt)
	})
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}

func TestApplyListenOptionsDoesNotApplyBroadcastUnix(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 0); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("UDP-LISTEN:0,so-broadcast")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyListenOptions(fd, mustDecodeAddress(t, spec), "udp4"); err != nil {
		t.Fatal(err)
	}
	if got := unixSockoptInt(t, fd, unix.SO_BROADCAST); got != 0 {
		t.Fatalf("ApplyListenOptions applied PH_PASTSOCKET broadcast: SO_BROADCAST=%d", got)
	}
}
