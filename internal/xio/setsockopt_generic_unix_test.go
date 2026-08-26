//go:build unix

package xio

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestApplyTCPConnOptsSetsockoptIntKeepaliveUnix(t *testing.T) {
	cli, srv := tcpPair(t)
	spec, err := parse.ParseSpec(fmt.Sprintf("TCP4:127.0.0.1:1,setsockopt-int=%d:%d:1", solSocket, soKeepalive))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTCPConnOpts(spec, cli); err != nil {
		t.Fatal(err)
	}
	if got := tcpSockoptInt(t, cli, soKeepalive); got != 1 {
		t.Fatalf("client SO_KEEPALIVE=%d want 1", got)
	}
	if err := ApplyTCPConnOpts(spec, srv); err != nil {
		t.Fatal(err)
	}
	if got := tcpSockoptInt(t, srv, soKeepalive); got != 1 {
		t.Fatalf("accepted SO_KEEPALIVE=%d want 1", got)
	}
}

func TestApplyTCPConnOptsSetsockoptDalanHexUnix(t *testing.T) {
	cli, _ := tcpPair(t)
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, 1)
	spec, err := parse.ParseSpec(fmt.Sprintf("TCP4:127.0.0.1:1,setsockopt=%d:%d:x%s", solSocket, soKeepalive, hex.EncodeToString(b)))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTCPConnOpts(spec, cli); err != nil {
		t.Fatal(err)
	}
	if got := tcpSockoptInt(t, cli, soKeepalive); got != 1 {
		t.Fatalf("SO_KEEPALIVE=%d want 1 after dalan hex", got)
	}
}

func TestApplyTCPConnOptsSetsockoptConnectedAliasUnix(t *testing.T) {
	cli, _ := tcpPair(t)
	spec, err := parse.ParseSpec(fmt.Sprintf("TCP4:127.0.0.1:1,sockopt-conn=%d:%d:1", solSocket, soKeepalive))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTCPConnOpts(spec, cli); err != nil {
		t.Fatal(err)
	}
	if got := tcpSockoptInt(t, cli, soKeepalive); got != 1 {
		t.Fatalf("SO_KEEPALIVE=%d want 1", got)
	}
}

func TestApplyTCPConnOptsSetsockoptThroughNetConnUnwrapUnix(t *testing.T) {
	cli, _ := tcpPair(t)
	spec, err := parse.ParseSpec(fmt.Sprintf("TCP4:127.0.0.1:1,setsockopt-int=%d:%d:1", solSocket, soKeepalive))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTCPConnOpts(spec, netConnUnwrapper{Conn: cli}); err != nil {
		t.Fatal(err)
	}
	if got := tcpSockoptInt(t, cli, soKeepalive); got != 1 {
		t.Fatalf("SO_KEEPALIVE=%d want 1 through NetConn unwrap", got)
	}
}

func TestApplyUDPConnOptsAppliesSetsockoptUnix(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	spec, err := parse.ParseSpec(fmt.Sprintf("UDP4:127.0.0.1:9,setsockopt=%d:%d:1", solSocket, soKeepalive))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyUDPConnOpts(c, spec, "udp4"); err != nil {
		t.Fatalf("UDP setsockopt must apply, not no-op: %v", err)
	}
	if got := udpSockoptInt(t, c, soKeepalive); got != 1 {
		t.Fatalf("SO_KEEPALIVE=%d want 1", got)
	}
}

func TestApplyTCPConnOptsAppliesSetsockoptOnUDPUnix(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	spec, err := parse.ParseSpec(fmt.Sprintf("UDP4:127.0.0.1:9,setsockopt=%d:%d:1", solSocket, soKeepalive))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTCPConnOpts(spec, c); err != nil {
		t.Fatalf("UDP setsockopt must apply, not no-op: %v", err)
	}
	if got := udpSockoptInt(t, c, soKeepalive); got != 1 {
		t.Fatalf("SO_KEEPALIVE=%d want 1 after ApplyTCPConnOpts on UDP", got)
	}
}

func TestListenControlSetsockoptPhasesUnix(t *testing.T) {
	connected, err := parse.ParseSpec(fmt.Sprintf("TCP4-LISTEN:0,setsockopt=%d:%d:1", solSocket, soKeepalive))
	if err != nil {
		t.Fatal(err)
	}
	lc := net.ListenConfig{Control: ListenControl(connected)}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if got := listenerSockoptInt(t, ln, soKeepalive); got != 0 {
		t.Fatalf("listener SO_KEEPALIVE=%d: CONNECTED setsockopt must not apply before bind", got)
	}

	past, err := parse.ParseSpec(fmt.Sprintf("TCP4-LISTEN:0,setsockopt-socket=%d:%d:1", solSocket, soKeepalive))
	if err != nil {
		t.Fatal(err)
	}
	lc = net.ListenConfig{Control: ListenControl(past)}
	ln2, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln2.Close() })
	if got := listenerSockoptInt(t, ln2, soKeepalive); got != 1 {
		t.Fatalf("listener SO_KEEPALIVE=%d want 1 after setsockopt-socket", got)
	}

	listen, err := parse.ParseSpec(fmt.Sprintf("TCP4-LISTEN:0,setsockopt-listen=%d:%d:1", solSocket, soKeepalive))
	if err != nil {
		t.Fatal(err)
	}
	lc = net.ListenConfig{Control: ListenControl(listen)}
	ln3, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln3.Close() })
	if got := listenerSockoptInt(t, ln3, soKeepalive); got != 1 {
		t.Fatalf("listener SO_KEEPALIVE=%d want 1 after setsockopt-listen PREBIND", got)
	}
}

func TestApplySetsockoptKernelRejectedUnix(t *testing.T) {
	cli, _ := tcpPair(t)
	// Classic SETSOCKOPT MSS=1: IPPROTO_TCP + TCP_MAXSEG + 1 is rejected.
	spec, err := parse.ParseSpec(fmt.Sprintf("TCP4:127.0.0.1:1,setsockopt=%d:%d:1", unix.IPPROTO_TCP, unix.TCP_MAXSEG))
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyTCPConnOpts(spec, cli)
	if err == nil {
		t.Fatal("TCP_MAXSEG=1 must fail the open, not succeed silently")
	}
}

func TestApplyGenericSetsockoptInvalidOptionUnix(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:9,setsockopt=-1:-1:1")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyUDPConnOpts(c, spec, "udp4"); err == nil {
		t.Fatal("invalid level/opt must fail, not succeed silently")
	}
}

func listenerSockoptInt(t *testing.T, ln net.Listener, opt int) int {
	t.Helper()
	sc, ok := ln.(syscall.Conn)
	if !ok {
		t.Fatalf("listener type %T is not syscall.Conn", ln)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		v, gerr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, opt)
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}
