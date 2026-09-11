//go:build linux

package xio

import (
	"context"
	"errors"
	"net"
	"os"
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

func TestDarwinTCPNopushUnsupportedOnLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	for _, opt := range []string{"nopush", "noopt", "tcp-nopush=1", "tcp-noopt=0"} {
		spec, err := parse.ParseSpec("TCP:127.0.0.1:9," + opt)
		if err != nil {
			t.Fatal(err)
		}
		err = ApplySocketOptions(fd, spec)
		if err == nil || !errors.Is(err, errNamedOptUnsupported) {
			t.Fatalf("%s on Linux: %v want %v", opt, err, errNamedOptUnsupported)
		}
	}
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
	if err := ApplySocketOptions(fd, spec); err != nil {
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
		if err := ApplySocketOptions(fd, spec); err == nil {
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

func assertOpenSpecEXECChildSOPriority(t *testing.T, specText string, mode Mode) {
	t.Helper()
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	if _, err := os.Stat("/bin/true"); err != nil {
		t.Skip("/bin/true not available")
	}
	spec, err := parse.ParseSpec(specText)
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
	o, err := OpenSpec(context.Background(), spec, mode, &Global{Log: logx.New()})
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

func TestOpenSpecEXECSocketpairAppliesSOPriorityLinux(t *testing.T) {
	assertOpenSpecEXECChildSOPriority(t, "EXEC:/bin/true,so-priority=5", ModeRDWR)
}

func TestOpenSpecEXECClassicSocketpairAppliesSOPriorityLinux(t *testing.T) {
	// Classic uses socketpair for these (including without PASTSOCKET).
	tests := []struct {
		name string
		spec string
		mode Mode
	}{
		{name: "fdin-fdout", spec: "EXEC:/bin/true,fdin=3,fdout=4,so-priority=5", mode: ModeRDWR},
		{name: "implicit-read", spec: "EXEC:/bin/true,so-priority=5", mode: ModeRead},
		{name: "implicit-write", spec: "EXEC:/bin/true,so-priority=5", mode: ModeWrite},
		{name: "end-close", spec: "EXEC:/bin/true,end-close,so-priority=5", mode: ModeRDWR},
		{name: "end-close-fdin-fdout", spec: "EXEC:/bin/true,end-close,fdin=3,fdout=4,so-priority=5", mode: ModeRDWR},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertOpenSpecEXECChildSOPriority(t, tc.spec, tc.mode)
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
	prepared, err := PrepareSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	err = runExecNoFork(context.Background(), nil, spec, prepared.Config, &Global{Log: logx.New()}, ModeRDWR)
	if err == nil {
		t.Fatal("expected leftover PASTSOCKET error")
	}
	if !strings.Contains(err.Error(), `option "so-priority" not inquired`) {
		t.Fatalf("err=%v want option %q not inquired", err, "so-priority")
	}
}
