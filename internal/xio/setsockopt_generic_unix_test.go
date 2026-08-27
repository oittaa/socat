//go:build unix

package xio

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
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
	if got := tcpSockoptInt(t, cli, soKeepalive); !sockoptFlagOn(got) {
		t.Fatalf("client SO_KEEPALIVE=%d want enabled", got)
	}
	if err := ApplyTCPConnOpts(spec, srv); err != nil {
		t.Fatal(err)
	}
	if got := tcpSockoptInt(t, srv, soKeepalive); !sockoptFlagOn(got) {
		t.Fatalf("accepted SO_KEEPALIVE=%d want enabled", got)
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
	if got := tcpSockoptInt(t, cli, soKeepalive); !sockoptFlagOn(got) {
		t.Fatalf("SO_KEEPALIVE=%d want enabled after dalan hex", got)
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
	if got := tcpSockoptInt(t, cli, soKeepalive); !sockoptFlagOn(got) {
		t.Fatalf("SO_KEEPALIVE=%d want enabled", got)
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
	if got := tcpSockoptInt(t, cli, soKeepalive); !sockoptFlagOn(got) {
		t.Fatalf("SO_KEEPALIVE=%d want enabled through NetConn unwrap", got)
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
	if got := udpSockoptInt(t, c, soKeepalive); !sockoptFlagOn(got) {
		t.Fatalf("SO_KEEPALIVE=%d want enabled", got)
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
	if got := udpSockoptInt(t, c, soKeepalive); !sockoptFlagOn(got) {
		t.Fatalf("SO_KEEPALIVE=%d want enabled after ApplyTCPConnOpts on UDP", got)
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
	if got := listenerSockoptInt(t, ln2, soKeepalive); !sockoptFlagOn(got) {
		t.Fatalf("listener SO_KEEPALIVE=%d want enabled after setsockopt-socket", got)
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
	if got := listenerSockoptInt(t, ln3, soKeepalive); !sockoptFlagOn(got) {
		t.Fatalf("listener SO_KEEPALIVE=%d want enabled after setsockopt-listen PREBIND", got)
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

// sockoptFlagOn reports whether a SOL_SOCKET boolean option is enabled.
// Linux returns 1; Darwin returns the so_options bit (SO_KEEPALIVE is 8).
func sockoptFlagOn(v int) bool { return v != 0 }

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

func TestApplyGenericSetsockoptOriginalOrderUnix(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	spec, err := parse.ParseSpec(fmt.Sprintf(
		"TCP:127.0.0.1:9,setsockopt-int=%d:%d:1,setsockopt=%d:%d:1",
		solSocket, soKeepalive, solSocket, unix.SO_OOBINLINE,
	))
	if err != nil {
		t.Fatal(err)
	}
	opts := sockoptOptOrder(t, func() {
		if err := ApplyGenericSetsockopt(fd, spec, SockoptPhaseConnected); err != nil {
			t.Fatal(err)
		}
	})
	if len(opts) < 2 || opts[0] != soKeepalive || opts[1] != unix.SO_OOBINLINE {
		t.Fatalf("order=%v want keepalive then oobinline", opts)
	}

	rev, err := parse.ParseSpec(fmt.Sprintf(
		"TCP:127.0.0.1:9,setsockopt=%d:%d:1,setsockopt-int=%d:%d:1",
		solSocket, unix.SO_OOBINLINE, solSocket, soKeepalive,
	))
	if err != nil {
		t.Fatal(err)
	}
	opts = sockoptOptOrder(t, func() {
		if err := ApplyGenericSetsockopt(fd, rev, SockoptPhaseConnected); err != nil {
			t.Fatal(err)
		}
	})
	if len(opts) < 2 || opts[0] != unix.SO_OOBINLINE || opts[1] != soKeepalive {
		t.Fatalf("reverse order=%v want oobinline then keepalive", opts)
	}
}

func TestApplyGenericSetsockoptRepeatedAndAliasUnix(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	spec, err := parse.ParseSpec(fmt.Sprintf(
		"TCP:127.0.0.1:9,setsockopt-int=%d:%d:1,setsockopt-int=%d:%d:0",
		solSocket, soKeepalive, solSocket, soKeepalive,
	))
	if err != nil {
		t.Fatal(err)
	}
	var values []int
	restore := SetSockoptTestHook(func(c SockoptCall) {
		if c.AsInt && c.Opt == soKeepalive {
			values = append(values, c.IntValue)
		}
	})
	defer restore()
	if err := ApplyGenericSetsockopt(fd, spec, SockoptPhaseConnected); err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 || values[0] != 1 || values[1] != 0 {
		t.Fatalf("repeated values=%v want [1 0]", values)
	}

	alias, err := parse.ParseSpec(fmt.Sprintf(
		"TCP:127.0.0.1:9,sockopt-int=%d:%d:1,setsockopt-int=%d:%d:1",
		solSocket, soKeepalive, solSocket, unix.SO_OOBINLINE,
	))
	if err != nil {
		t.Fatal(err)
	}
	opts := sockoptOptOrder(t, func() {
		if err := ApplyGenericSetsockopt(fd, alias, SockoptPhaseConnected); err != nil {
			t.Fatal(err)
		}
	})
	if len(opts) < 2 || opts[0] != soKeepalive || opts[1] != unix.SO_OOBINLINE {
		t.Fatalf("alias+canonical order=%v", opts)
	}
}

func TestDialTCPAllWrapCommonOnceKeepaliveUnix(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	spec, err := parse.ParseSpec(fmt.Sprintf("TCP4:127.0.0.1:%d,setsockopt-int=%d:%d:1", port, solSocket, soKeepalive))
	if err != nil {
		t.Fatal(err)
	}
	var n int
	restore := SetSockoptTestHook(func(c SockoptCall) {
		if c.Opt == soKeepalive {
			n++
		}
	})
	defer restore()
	c, err := DialTCPAll(context.Background(), "tcp4", "127.0.0.1", fmt.Sprintf("%d", port), spec, nil, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := WrapCommonAfterConnected(spec, relay.NetStream{Conn: c}); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("SO_KEEPALIVE setsockopt count=%d want 1", n)
	}
}

func TestDialControlPrebindBeforeConnectUnix(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	spec, err := parse.ParseSpec(fmt.Sprintf("TCP4:127.0.0.1:%d,setsockopt-listen=%d:%d:1", port, solSocket, soKeepalive))
	if err != nil {
		t.Fatal(err)
	}
	var events []string
	restore := SetSockoptTestHook(func(c SockoptCall) {
		if c.Opt == soKeepalive {
			events = append(events, "prebind")
		}
	})
	defer restore()
	c, err := DialTCPAll(context.Background(), "tcp4", "127.0.0.1", fmt.Sprintf("%d", port), spec, nil, 0, func(string, string, syscall.RawConn) error {
		events = append(events, "control-done")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	events = append(events, "dial-done")
	if strings.Join(events, ",") != "prebind,control-done,dial-done" {
		t.Fatalf("events=%v want prebind then control-done then dial-done", events)
	}
}

func TestListenControlPastSocketThenPrebindThenBindUnix(t *testing.T) {
	spec, err := parse.ParseSpec(fmt.Sprintf(
		"TCP4-LISTEN:0,setsockopt-socket=%d:%d:1,setsockopt-listen=%d:%d:1",
		solSocket, soKeepalive, solSocket, unix.SO_OOBINLINE,
	))
	if err != nil {
		t.Fatal(err)
	}
	var events []string
	restore := SetSockoptTestHook(func(c SockoptCall) {
		switch c.Opt {
		case soKeepalive:
			events = append(events, "socket")
		case unix.SO_OOBINLINE:
			events = append(events, "listen")
		}
	})
	defer restore()
	inner := ListenControl(spec)
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		if err := inner(network, address, c); err != nil {
			return err
		}
		events = append(events, "control-done")
		return nil
	}}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	events = append(events, "listen-done")
	if len(events) < 4 {
		t.Fatalf("events=%v", events)
	}
	if events[len(events)-2] != "control-done" || events[len(events)-1] != "listen-done" {
		t.Fatalf("events=%v want Control to return before bind", events)
	}
	phases := events[:len(events)-2]
	if len(phases) == 0 || phases[0] != "socket" {
		t.Fatalf("events=%v want PASTSOCKET before PREBIND", events)
	}
	for i := 0; i+1 < len(phases); i += 2 {
		if phases[i] != "socket" || phases[i+1] != "listen" {
			t.Fatalf("events=%v want repeating PASTSOCKET then PREBIND", events)
		}
	}
}

func sockoptOptOrder(t *testing.T, fn func()) []int {
	t.Helper()
	var opts []int
	restore := SetSockoptTestHook(func(c SockoptCall) {
		opts = append(opts, c.Opt)
	})
	defer restore()
	fn()
	return opts
}
