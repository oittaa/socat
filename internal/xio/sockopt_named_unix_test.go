//go:build linux || darwin

package xio

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestApplySocketOptionsDontrouteOobinlineUnix(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	if got := unixSockoptInt(t, fd, unix.SO_DONTROUTE); got != 0 {
		t.Fatalf("SO_DONTROUTE default=%d want 0", got)
	}
	if got := unixSockoptInt(t, fd, unix.SO_OOBINLINE); got != 0 {
		t.Fatalf("SO_OOBINLINE default=%d want 0", got)
	}

	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,dontroute,so-oobinline=1")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, spec); err != nil {
		t.Fatal(err)
	}
	if got := unixSockoptInt(t, fd, unix.SO_DONTROUTE); !sockoptFlagOn(got) {
		t.Fatalf("SO_DONTROUTE=%d want enabled", got)
	}
	if got := unixSockoptInt(t, fd, unix.SO_OOBINLINE); !sockoptFlagOn(got) {
		t.Fatalf("SO_OOBINLINE=%d want enabled", got)
	}

	off, err := parse.ParseSpec("TCP:127.0.0.1:9,so-dontroute=0,oobinline=0")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, off); err != nil {
		t.Fatal(err)
	}
	if got := unixSockoptInt(t, fd, unix.SO_DONTROUTE); got != 0 {
		t.Fatalf("SO_DONTROUTE=%d want 0", got)
	}
	if got := unixSockoptInt(t, fd, unix.SO_OOBINLINE); got != 0 {
		t.Fatalf("SO_OOBINLINE=%d want 0", got)
	}
}

func TestApplySocketOptionsDebugUnix(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,so-debug")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplySocketOptions(fd, spec)
	if err != nil {
		if !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM) {
			t.Fatalf("so-debug: %v", err)
		}
		return
	}
	if got := unixSockoptInt(t, fd, unix.SO_DEBUG); !sockoptFlagOn(got) {
		t.Fatalf("SO_DEBUG=%d want enabled (not a silent no-op)", got)
	}
}

func TestApplySocketOptionsDontrouteOnUDPUnix(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	spec, err := parse.ParseSpec("UDP:127.0.0.1:9,so-dontroute")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, spec); err != nil {
		t.Fatal(err)
	}
	if got := unixSockoptInt(t, fd, unix.SO_DONTROUTE); !sockoptFlagOn(got) {
		t.Fatalf("UDP SO_DONTROUTE=%d want enabled", got)
	}
}

func TestLinuxOnlyNamedTCPUnsupportedOffLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux implements TCP_CORK")
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	for _, opt := range []string{"tcp-cork", "sctp-nodelay", "sctp-maxseg=1400", "so-priority=6", "so-passcred", "nocheck"} {
		spec, err := parse.ParseSpec("TCP:127.0.0.1:9," + opt)
		if err != nil {
			t.Fatal(err)
		}
		err = ApplySocketOptions(fd, spec)
		if err == nil || !errors.Is(err, errNamedOptUnsupported) {
			t.Fatalf("%s off Linux: %v want %v", opt, err, errNamedOptUnsupported)
		}
	}
}

func TestApplySocketOptionsRejectsInvalidNamedIntUnix(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	for _, specText := range []string{
		"TCP:127.0.0.1:9,dontroute=no",
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

func TestNamedAndGenericAllCommandLineOrderUnix(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options string
		want    []int
	}{
		{
			name:    "named-then-generic",
			options: fmt.Sprintf("so-dontroute=1,setsockopt-int=%d:%d:0", solSocket, soDontroute),
			want:    []int{1, 0},
		},
		{
			name:    "generic-then-named",
			options: fmt.Sprintf("setsockopt-int=%d:%d:0,so-dontroute=1", solSocket, soDontroute),
			want:    []int{0, 1},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Close(fd) })
			spec, err := parse.ParseSpec("SOCKETPAIR," + tc.options)
			if err != nil {
				t.Fatal(err)
			}
			calls := sockoptOptCalls(t, func() {
				if err := ApplyGenericSetsockoptAll(fd, spec); err != nil {
					t.Fatal(err)
				}
			})
			var got []int
			for _, call := range calls {
				if call.Level == solSocket && call.Opt == soDontroute {
					got = append(got, call.IntValue)
				}
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("SO_DONTROUTE values=%v want %v", got, tc.want)
			}
		})
	}
}

func TestListenControlAppliesDontrouteUnix(t *testing.T) {
	spec, err := parse.ParseSpec("TCP4-LISTEN:0,so-dontroute")
	if err != nil {
		t.Fatal(err)
	}
	lc := NewTCPListenConfig(spec)
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if got := listenerSockoptInt(t, ln, unix.SO_DONTROUTE); !sockoptFlagOn(got) {
		t.Fatalf("listener SO_DONTROUTE=%d want enabled", got)
	}
}

func TestApplyTCPConnOptsDoesNotApplyPastSocketNamedUnix(t *testing.T) {
	cli, _ := tcpPair(t)
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,so-dontroute")
	if err != nil {
		t.Fatal(err)
	}
	if got := tcpSockoptInt(t, cli, unix.SO_DONTROUTE); got != 0 {
		t.Fatalf("precondition SO_DONTROUTE=%d want 0", got)
	}
	if err := ApplyTCPConnOpts(spec, cli); err != nil {
		t.Fatal(err)
	}
	if got := tcpSockoptInt(t, cli, unix.SO_DONTROUTE); got != 0 {
		t.Fatalf("ApplyTCPConnOpts applied PH_PASTSOCKET so-dontroute: SO_DONTROUTE=%d", got)
	}
}

func TestApplyTCPConnOptsNamedConnectedOnUDPUnix(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:9,tcp-maxseg-late=512")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyTCPConnOpts(spec, c)
	if err == nil {
		t.Fatal("tcp-maxseg-late on UDP must fail, not no-op")
	}
}

func TestFDRejectsMaxsegLateUnix(t *testing.T) {
	spec, err := parse.ParseSpec("FD:0,tcp-maxseg-late=512")
	if err != nil {
		t.Fatal(err)
	}
	err = RejectGenericSetsockoptPhases(spec, "FD", SockoptPhasePrebind, SockoptPhaseConnected)
	if err == nil || !strings.Contains(err.Error(), "not supported at this lifecycle phase") {
		t.Fatalf("error=%v want CONNECTED phase rejection", err)
	}
}

func sockoptOptCalls(t *testing.T, fn func()) []SockoptCall {
	t.Helper()
	var calls []SockoptCall
	restore := SetSockoptTestHook(func(c SockoptCall) {
		calls = append(calls, c)
	})
	t.Cleanup(restore)
	fn()
	return calls
}

func TestNamedConnectedMaxsegLateWithGenericOrderUnix(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	spec, err := parse.ParseSpec(fmt.Sprintf("TCP:127.0.0.1:9,tcp-maxseg-late=512,setsockopt-int=%d:%d:1", solSocket, soKeepalive))
	if err != nil {
		t.Fatal(err)
	}
	calls := sockoptOptCalls(t, func() {
		if err := ApplyGenericSetsockopt(fd, spec, SockoptPhaseConnected); err != nil && !errors.Is(err, syscall.EINVAL) {
			t.Fatal(err)
		}
	})
	if len(calls) < 2 {
		t.Fatalf("calls=%d want at least maxseg then keepalive", len(calls))
	}
	if calls[0].Level != unix.IPPROTO_TCP || calls[0].Opt != unix.TCP_MAXSEG || calls[0].IntValue != 512 {
		t.Fatalf("first call=%+v want TCP_MAXSEG=512", calls[0])
	}
	if calls[1].Opt != soKeepalive {
		t.Fatalf("second call opt=%d want SO_KEEPALIVE", calls[1].Opt)
	}
}
