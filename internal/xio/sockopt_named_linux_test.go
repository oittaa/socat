//go:build linux

package xio

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/logx"
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

func TestPastSocketTCPNamedAndGenericCommandLineOrderLinux(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options string
		want    []int
	}{
		{
			name:    "named-then-generic",
			options: fmt.Sprintf("tcp-cork=1,setsockopt-socket=%d:%d:0", unix.IPPROTO_TCP, unix.TCP_CORK),
			want:    []int{1, 0},
		},
		{
			name:    "generic-then-named",
			options: fmt.Sprintf("setsockopt-socket=%d:%d:0,tcp-cork=1", unix.IPPROTO_TCP, unix.TCP_CORK),
			want:    []int{0, 1},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Close(fd) })
			spec, err := parse.ParseSpec("TCP:127.0.0.1:9," + tc.options)
			if err != nil {
				t.Fatal(err)
			}
			var got []int
			restore := SetSockoptTestHook(func(call SockoptCall) {
				if call.Level == unix.IPPROTO_TCP && call.Opt == unix.TCP_CORK {
					got = append(got, call.IntValue)
				}
			})
			t.Cleanup(restore)
			if err := ApplySocketOptions(fd, spec); err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("TCP_CORK values=%v want %v", got, tc.want)
			}
		})
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

func TestApplySocketOptionsPriorityPasscredNocheckLinux(t *testing.T) {
	// Classic xio-socket.c opt_so_priority / opt_so_passcred / opt_so_no_check
	// (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
	// af5388c898c7bb60997935aee93c223deba60c4a): GROUP_SOCKET, PH_PASTSOCKET,
	// TYPE_INT, OFUNC_SOCKOPT, SOL_SOCKET.
	//
	// SO_PRIORITY and SO_NO_CHECK stick on AF_INET here. SO_PASSCRED is a
	// UNIX-domain credential option: some kernels (GitHub Actions) return
	// EOPNOTSUPP on TCP/UDP. Classic still applies it on GROUP_SOCKET and
	// surfaces the kernel error; tests require success on UNIX and accept
	// a precise ENOPROTOOPT/EOPNOTSUPP on INET (never a silent no-op).
	for _, tc := range []struct {
		name    string
		network int
		proto   int
		spec    string
		opt     int
		want    int
	}{
		{name: "tcp-priority", network: unix.SOCK_STREAM, proto: 0, spec: "TCP:127.0.0.1:9,so-priority=6", opt: unix.SO_PRIORITY, want: 6},
		{name: "udp-priority-alias", network: unix.SOCK_DGRAM, proto: unix.IPPROTO_UDP, spec: "UDP:127.0.0.1:9,priority=3", opt: unix.SO_PRIORITY, want: 3},
		{name: "udp-nocheck", network: unix.SOCK_DGRAM, proto: unix.IPPROTO_UDP, spec: "UDP:127.0.0.1:9,nocheck", opt: unix.SO_NO_CHECK, want: 1},
		{name: "tcp-no-check-alias", network: unix.SOCK_STREAM, proto: 0, spec: "TCP:127.0.0.1:9,no-check=1", opt: unix.SO_NO_CHECK, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd, err := unix.Socket(unix.AF_INET, tc.network, tc.proto)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Close(fd) })
			spec, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			if err := ApplySocketOptions(fd, spec); err != nil {
				t.Fatal(err)
			}
			got, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, tc.opt)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("getsockopt=%d want %d", got, tc.want)
			}
		})
	}

	t.Run("unix-passcred-priority", func(t *testing.T) {
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		spec, err := parse.ParseSpec("UNIX-CONNECT:/tmp/sock,so-passcred=1,so-priority=4")
		if err != nil {
			t.Fatal(err)
		}
		if err := ApplySocketOptions(fd, spec); err != nil {
			t.Fatal(err)
		}
		if got, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED); err != nil || got != 1 {
			t.Fatalf("UNIX SO_PASSCRED=%d err=%v want 1", got, err)
		}
		if got, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PRIORITY); err != nil || got != 4 {
			t.Fatalf("UNIX SO_PRIORITY=%d err=%v want 4", got, err)
		}
	})
}

func TestApplySocketOptionsPasscredOnINETLinux(t *testing.T) {
	for _, tc := range []struct {
		name    string
		network int
		proto   int
		spec    string
		want    int
	}{
		{name: "tcp-passcred", network: unix.SOCK_STREAM, proto: 0, spec: "TCP:127.0.0.1:9,so-passcred", want: 1},
		{name: "udp-passcred-clear", network: unix.SOCK_DGRAM, proto: unix.IPPROTO_UDP, spec: "UDP:127.0.0.1:9,passcred=0", want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd, err := unix.Socket(unix.AF_INET, tc.network, tc.proto)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Close(fd) })
			spec, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			err = ApplySocketOptions(fd, spec)
			if err != nil {
				if errors.Is(err, unix.ENOPROTOOPT) || errors.Is(err, unix.EOPNOTSUPP) {
					return
				}
				t.Fatal(err)
			}
			got, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("getsockopt SO_PASSCRED=%d want %d", got, tc.want)
			}
		})
	}
}

func TestPastSocketPriorityAndGenericCommandLineOrderLinux(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options string
		want    []int
	}{
		{
			name:    "named-then-generic",
			options: fmt.Sprintf("so-priority=6,setsockopt-socket=%d:%d:1", unix.SOL_SOCKET, unix.SO_PRIORITY),
			want:    []int{6, 1},
		},
		{
			name:    "generic-then-named",
			options: fmt.Sprintf("setsockopt-socket=%d:%d:1,priority=6", unix.SOL_SOCKET, unix.SO_PRIORITY),
			want:    []int{1, 6},
		},
		{
			name:    "alias-then-canonical",
			options: "priority=1,so-priority=6",
			want:    []int{1, 6},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Close(fd) })
			spec, err := parse.ParseSpec("TCP:127.0.0.1:9," + tc.options)
			if err != nil {
				t.Fatal(err)
			}
			var got []int
			restore := SetSockoptTestHook(func(call SockoptCall) {
				if call.Level == unix.SOL_SOCKET && call.Opt == unix.SO_PRIORITY {
					got = append(got, call.IntValue)
				}
			})
			t.Cleanup(restore)
			if err := ApplySocketOptions(fd, spec); err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("SO_PRIORITY values=%v want %v", got, tc.want)
			}
		})
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
	if err := ApplySocketOptions(fd, spec); err == nil {
		t.Fatal("so-priority=no must fail")
	}
}

func TestListenControlAppliesPriorityLinux(t *testing.T) {
	spec, err := parse.ParseSpec("TCP4-LISTEN:0,so-priority=5")
	if err != nil {
		t.Fatal(err)
	}
	lc := NewTCPListenConfig(spec)
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	sc, ok := ln.(syscall.Conn)
	if !ok {
		t.Fatalf("listener type %T is not syscall.Conn", ln)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got int
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		got, gerr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PRIORITY)
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	if got != 5 {
		t.Fatalf("listener SO_PRIORITY=%d want 5", got)
	}
}

func TestApplyTCPConnOptsDoesNotApplyPastSocketPriorityLinux(t *testing.T) {
	cli, _ := tcpPair(t)
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,so-priority=6")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := cli.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var before int
	_ = raw.Control(func(fd uintptr) {
		before, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PRIORITY)
	})
	if err := ApplyTCPConnOpts(spec, cli); err != nil {
		t.Fatal(err)
	}
	var after int
	_ = raw.Control(func(fd uintptr) {
		after, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PRIORITY)
	})
	if after != before {
		t.Fatalf("ApplyTCPConnOpts applied PH_PASTSOCKET so-priority: %d → %d", before, after)
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

func TestApplySocketOptionsPastSocketPriorityAndSndbufOrderLinux(t *testing.T) {
	type step struct{ opt, value int }
	for _, tc := range []struct {
		name    string
		options string
		want    []step
	}{
		{
			name:    "priority-then-sndbuf",
			options: "so-priority=3,sndbuf=4096",
			want:    []step{{unix.SO_PRIORITY, 3}, {unix.SO_SNDBUF, 4096}},
		},
		{
			name:    "sndbuf-then-priority",
			options: "sndbuf=4096,so-priority=3",
			want:    []step{{unix.SO_SNDBUF, 4096}, {unix.SO_PRIORITY, 3}},
		},
		{
			name:    "broadcast-then-priority",
			options: "broadcast,so-priority=3",
			want:    []step{{unix.SO_BROADCAST, 1}, {unix.SO_PRIORITY, 3}},
		},
		{
			name:    "repeated-sndbuf",
			options: "so-priority=3,sndbuf=4096,sndbuf=8192",
			want:    []step{{unix.SO_PRIORITY, 3}, {unix.SO_SNDBUF, 4096}, {unix.SO_SNDBUF, 8192}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Close(fd) })
			spec, err := parse.ParseSpec("TCP:127.0.0.1:9," + tc.options)
			if err != nil {
				t.Fatal(err)
			}
			var got []step
			restore := SetSockoptTestHook(func(call SockoptCall) {
				if call.Level != unix.SOL_SOCKET || !call.AsInt {
					return
				}
				switch call.Opt {
				case unix.SO_PRIORITY, unix.SO_SNDBUF, unix.SO_BROADCAST:
					got = append(got, step{call.Opt, call.IntValue})
				}
			})
			t.Cleanup(restore)
			if err := ApplySocketOptions(fd, spec); err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("setsockopt order=%v want %v", got, tc.want)
			}
		})
	}
}

func TestApplyGenericSetsockoptAllPriorityAndSndbufOrderLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	spec, err := parse.ParseSpec("SOCKETPAIR,so-priority=3,sndbuf=4096")
	if err != nil {
		t.Fatal(err)
	}
	type step struct{ opt, value int }
	var got []step
	restore := SetSockoptTestHook(func(call SockoptCall) {
		if call.Level != unix.SOL_SOCKET || !call.AsInt {
			return
		}
		switch call.Opt {
		case unix.SO_PRIORITY, unix.SO_SNDBUF:
			got = append(got, step{call.Opt, call.IntValue})
		}
	})
	t.Cleanup(restore)
	if err := ApplyGenericSetsockoptAll(fd, spec); err != nil {
		t.Fatal(err)
	}
	want := []step{{unix.SO_PRIORITY, 3}, {unix.SO_SNDBUF, 4096}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("SOCKETPAIR PH_ALL order=%v want %v", got, want)
	}
}

func TestOpenSpecEXECSocketpairAppliesSOPriorityLinux(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	if _, err := os.Stat("/bin/true"); err != nil {
		t.Skip("/bin/true not available")
	}
	spec, err := parse.ParseSpec("EXEC:/bin/true,so-priority=5")
	if err != nil {
		t.Fatal(err)
	}
	type hit struct{ fd, value int }
	var hits []hit
	restore := SetSockoptTestHook(func(c SockoptCall) {
		if c.AsInt && c.Level == unix.SOL_SOCKET && c.Opt == unix.SO_PRIORITY {
			hits = append(hits, hit{fd: c.FD, value: c.IntValue})
		}
	})
	t.Cleanup(restore)
	o, err := OpenSpec(context.Background(), spec, ModeRDWR, &Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if len(hits) != 1 {
		t.Fatalf("SO_PRIORITY applied %d times want 1 (child endpoint): %v", len(hits), hits)
	}
	if hits[0].value != 5 {
		t.Fatalf("SO_PRIORITY value=%d want 5", hits[0].value)
	}
	parent := asOSFile(o.Stream)
	if parent == nil {
		t.Fatal("parent EXEC stream has no *os.File")
	}
	parentFD := int(parent.Fd())
	if hits[0].fd == parentFD {
		t.Fatalf("SO_PRIORITY applied on parent fd %d", parentFD)
	}
	got, err := unix.GetsockoptInt(parentFD, unix.SOL_SOCKET, unix.SO_PRIORITY)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Fatalf("parent SO_PRIORITY=%d want 0 (classic popts on child only)", got)
	}
}

func TestOpenSpecEXECNonSocketpairRejectsPastSocketOptionsLinux(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	tests := []struct {
		name    string
		spec    string
		mode    Mode
		optName string
	}{
		{name: "pipes", spec: "EXEC:/bin/true,pipes,so-priority=5", mode: ModeRDWR, optName: "so-priority"},
		{name: "pipes-priority-alias", spec: "EXEC:/bin/true,pipes,priority=5", mode: ModeRDWR, optName: "so-priority"},
		{name: "pty", spec: "EXEC:/bin/true,pty,so-priority=5", mode: ModeRDWR, optName: "so-priority"},
		{name: "nofork", spec: "EXEC:/bin/true,nofork,so-priority=5", mode: ModeRDWR, optName: "so-priority"},
		{name: "end-close", spec: "EXEC:/bin/true,end-close,so-priority=5", mode: ModeRDWR, optName: "so-priority"},
		{name: "fdin-fdout", spec: "EXEC:/bin/true,fdin=3,fdout=4,so-priority=5", mode: ModeRDWR, optName: "so-priority"},
		{name: "implicit-read", spec: "EXEC:/bin/true,so-priority=5", mode: ModeRead, optName: "so-priority"},
		{name: "implicit-write", spec: "EXEC:/bin/true,so-priority=5", mode: ModeWrite, optName: "so-priority"},
		{name: "system-pipes", spec: "SYSTEM:/bin/true,pipes,so-priority=5", mode: ModeRDWR, optName: "so-priority"},
		{name: "setsockopt-socket-pipes", spec: "EXEC:/bin/true,pipes,setsockopt-socket=1:12:1", mode: ModeRDWR, optName: "setsockopt-socket"},
	}
	want := func(name string) string {
		return fmt.Sprintf("option %q not inquired", name)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			_, err = OpenSpec(context.Background(), spec, tc.mode, &Global{Log: logx.New()})
			if err == nil {
				t.Fatal("expected leftover PASTSOCKET error")
			}
			if !strings.Contains(err.Error(), want(tc.optName)) {
				t.Fatalf("err=%v want %s", err, want(tc.optName))
			}
		})
	}
}

func TestRunExecNoForkRejectsPastSocketOptionsLinux(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	spec, err := parse.ParseSpec("EXEC:/bin/true,nofork,so-priority=5")
	if err != nil {
		t.Fatal(err)
	}
	err = runExecNoFork(context.Background(), nil, spec, &Global{Log: logx.New()}, ModeRDWR)
	if err == nil {
		t.Fatal("expected leftover PASTSOCKET error")
	}
	if !strings.Contains(err.Error(), `option "so-priority" not inquired`) {
		t.Fatalf("err=%v want option %q not inquired", err, "so-priority")
	}
}
