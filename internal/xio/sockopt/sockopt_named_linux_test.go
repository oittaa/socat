//go:build linux

package sockopt_test

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/sockopt"
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

func TestApplySocketOptionsBareRcvlowatLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVLOWAT, 8); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,so-rcvlowat")
	if err != nil {
		t.Fatal(err)
	}
	if err := sockopt.ApplySocketOptions(fd, mustDecodeAddress(t, spec)); err != nil {
		t.Fatal(err)
	}
	if got := unixSockoptInt(t, fd, unix.SO_RCVLOWAT); got != 1 {
		t.Fatalf("bare so-rcvlowat set SO_RCVLOWAT=%d want 1", got)
	}
}

func TestApplySocketOptionsRejectsInvalidRcvlowatLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	for _, specText := range []string{
		"TCP:127.0.0.1:9,so-rcvlowat=no",
		"TCP:127.0.0.1:9,rcvlowat=",
	} {
		spec, err := parse.ParseSpec(specText)
		if err != nil {
			t.Fatal(err)
		}
		config, err := decodeAddress(spec)
		if err == nil {
			err = sockopt.ApplySocketOptions(fd, config)
		}
		if err == nil {
			t.Fatalf("%s: expected invalid value", specText)
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
	err = sockopt.ApplySocketOptions(fd, mustDecodeAddress(t, spec))
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
	err = sockopt.ApplySocketOptions(fd, mustDecodeAddress(t, spec))
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
	if err := sockopt.ApplySocketOptions(fd, mustDecodeAddress(t, spec)); err != nil {
		t.Fatal(err)
	}
	after := fdTCPSockoptInt(t, fd, unix.TCP_MAXSEG)
	if after == 512 && before != 512 {
		t.Fatalf("tcp-maxseg-late applied at PASTSOCKET: TCP_MAXSEG %d → %d", before, after)
	}
}

func TestListenControlAppliesDeferAcceptLinux(t *testing.T) {
	spec, err := parse.ParseSpec("TCP4-LISTEN:0,defer-accept=30")
	if err != nil {
		t.Fatal(err)
	}
	lc := xio.NewTCPListenConfig(mustDecodeAddress(t, spec))
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if got := listenerTCPSockoptInt(t, ln, unix.TCP_DEFER_ACCEPT); got < 30 {
		t.Fatalf("listener TCP_DEFER_ACCEPT=%d want >= 30", got)
	}
}

func TestApplySocketOptionsRejectsInvalidPriorityLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,so-priority=no")
	if err != nil {
		t.Fatal(err)
	}
	config, err := decodeAddress(spec)
	if err == nil {
		err = sockopt.ApplySocketOptions(fd, config)
	}
	if err == nil {
		t.Fatal("so-priority=no must fail")
	}
}

func TestApplyTCPConnOptsMaxsegLateThroughNetConnUnwrapLinux(t *testing.T) {
	cli, _ := tcpPair(t)
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,tcp-maxseg-late=1")
	if err != nil {
		t.Fatal(err)
	}
	err = xio.ApplyTCPConnOpts(mustDecodeAddress(t, spec), netConnUnwrapper{Conn: cli})
	if err == nil {
		t.Fatal("tcp-maxseg-late through NetConn unwrap must reach the kernel")
	}
}
