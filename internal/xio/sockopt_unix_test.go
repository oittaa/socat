//go:build linux || darwin

package xio

import (
	"context"
	"net"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/unix"
)

func TestApplySocketTimeosUnix(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	apply := func(specText string, rcvWant, sndWant time.Duration) {
		t.Helper()
		spec, err := parse.ParseSpec(specText)
		if err != nil {
			t.Fatal(err)
		}
		if err := ApplySocketTimeos(fd, spec); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name string
			opt  int
			want time.Duration
		}{
			{name: "receive", opt: soRcvtimeo, want: rcvWant},
			{name: "send", opt: soSndtimeo, want: sndWant},
		} {
			t.Run(tc.name, func(t *testing.T) {
				tv, err := unix.GetsockoptTimeval(fd, solSocket, tc.opt)
				if err != nil {
					t.Fatal(err)
				}
				if got := time.Duration(unix.TimevalToNsec(*tv)); got != tc.want {
					t.Fatalf("timeout=%v want %v", got, tc.want)
				}
			})
		}
	}

	// Whole seconds so the getsockopt round-trip is independent of kernel HZ
	// (SO_RCVTIMEO/SO_SNDTIMEO are stored in jiffies). Distinct values prove
	// rcvtimeo and sndtimeo are wired to different option constants.
	// Fractional conversion is covered by TestTimevalFromSpec.
	apply("UDP:127.0.0.1:9,rcvtimeo=1,sndtimeo=2", 1*time.Second, 2*time.Second)
	apply("UDP:127.0.0.1:9,rcvtimeo=0,sndtimeo=0", 0, 0)
}

func TestTimevalFromSpec(t *testing.T) {
	tests := []struct {
		value string
		sec   int64
		usec  int64
	}{
		{value: "0", sec: 0, usec: 0},
		{value: "1.25", sec: 1, usec: 250000},
		{value: "2.5", sec: 2, usec: 500000},
	}
	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			tv, err := timevalFromSpec(tc.value)
			if err != nil {
				t.Fatalf("timevalFromSpec(%q): %v", tc.value, err)
			}
			if int64(tv.Sec) != tc.sec || int64(tv.Usec) != tc.usec {
				t.Fatalf("timevalFromSpec(%q)=%+v want {Sec:%d Usec:%d}", tc.value, tv, tc.sec, tc.usec)
			}
		})
	}
}

func TestTimevalFromSpecRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{"-1", "banana", "NaN", "1e100"} {
		if _, err := timevalFromSpec(value); err == nil {
			t.Errorf("timevalFromSpec(%q) succeeded", value)
		}
	}
}

func TestApplySocketOptionsLingerUnix(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,linger=3")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, spec); err != nil {
		t.Fatal(err)
	}
	got, err := unix.GetsockoptLinger(fd, unix.SOL_SOCKET, unix.SO_LINGER)
	if err != nil {
		t.Fatal(err)
	}
	if got.Onoff != 1 || got.Linger != 3 {
		t.Fatalf("SO_LINGER=%+v want enabled, 3 seconds", got)
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

func TestApplySocketOptionsSndbufRcvbufUnix(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	spec, err := parse.ParseSpec("UDP:127.0.0.1:9,sndbuf=4096,rcvbuf=8192,sndbuf-late=65536,rcvbuf-late=131072")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, spec); err != nil {
		t.Fatal(err)
	}
	if got := unixSockoptInt(t, fd, unix.SO_SNDBUF); got < 4096 {
		t.Fatalf("SO_SNDBUF=%d want >= 4096 (late must not apply at PH_PASTSOCKET)", got)
	}
	if got := unixSockoptInt(t, fd, unix.SO_RCVBUF); got < 8192 {
		t.Fatalf("SO_RCVBUF=%d want >= 8192 (late must not apply at PH_PASTSOCKET)", got)
	}
	if got := unixSockoptInt(t, fd, unix.SO_SNDBUF); got >= 65536 {
		t.Fatalf("SO_SNDBUF=%d: sndbuf-late applied inside ApplySocketOptions", got)
	}
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
	if err := ApplySocketOptions(fd, spec); err == nil {
		t.Fatal("expected invalid sndbuf error")
	}
}

func TestWrapCommonAppliesSndbufLateOverEarlyUnix(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "sock")
	t.Cleanup(func() { _ = f.Close() })

	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,sndbuf=4096,rcvbuf=4096,sndbuf-late=65536,rcvbuf-late=65536")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, spec); err != nil {
		t.Fatal(err)
	}
	earlySnd := unixSockoptInt(t, fd, unix.SO_SNDBUF)
	earlyRcv := unixSockoptInt(t, fd, unix.SO_RCVBUF)
	if earlySnd < 4096 || earlyRcv < 4096 {
		t.Fatalf("early SO_SNDBUF=%d SO_RCVBUF=%d want >= 4096", earlySnd, earlyRcv)
	}

	if _, err := WrapCommon(spec, FileStream(f)); err != nil {
		t.Fatal(err)
	}
	lateSnd := unixSockoptInt(t, fd, unix.SO_SNDBUF)
	lateRcv := unixSockoptInt(t, fd, unix.SO_RCVBUF)
	if lateSnd < 65536 {
		t.Fatalf("SO_SNDBUF=%d want >= 65536 after WrapCommon (late wins)", lateSnd)
	}
	if lateRcv < 65536 {
		t.Fatalf("SO_RCVBUF=%d want >= 65536 after WrapCommon (late wins)", lateRcv)
	}
	if lateSnd <= earlySnd {
		t.Fatalf("SO_SNDBUF did not grow from early=%d to late=%d", earlySnd, lateSnd)
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

func TestApplyTCPConnOptsAppliesSndbufLateUnix(t *testing.T) {
	cli, srv := tcpPair(t)
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,sndbuf=4096,rcvbuf=4096,sndbuf-late=65536,rcvbuf-late=65536")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := cli.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optErr error
	_ = raw.Control(func(fd uintptr) {
		optErr = ApplySocketOptions(int(fd), spec)
	})
	if optErr != nil {
		t.Fatal(optErr)
	}
	earlySnd := tcpSockoptInt(t, cli, unix.SO_SNDBUF)
	earlyRcv := tcpSockoptInt(t, cli, unix.SO_RCVBUF)
	if earlySnd < 4096 || earlyRcv < 4096 {
		t.Fatalf("early SO_SNDBUF=%d SO_RCVBUF=%d want >= 4096", earlySnd, earlyRcv)
	}
	if earlySnd >= 65536 {
		t.Fatalf("SO_SNDBUF=%d: sndbuf-late applied before ApplyTCPConnOpts", earlySnd)
	}

	if err := ApplyTCPConnOpts(spec, cli); err != nil {
		t.Fatal(err)
	}
	lateSnd := tcpSockoptInt(t, cli, unix.SO_SNDBUF)
	lateRcv := tcpSockoptInt(t, cli, unix.SO_RCVBUF)
	if lateSnd < 65536 {
		t.Fatalf("SO_SNDBUF=%d want >= 65536 after ApplyTCPConnOpts", lateSnd)
	}
	if lateRcv < 65536 {
		t.Fatalf("SO_RCVBUF=%d want >= 65536 after ApplyTCPConnOpts", lateRcv)
	}
	if lateSnd <= earlySnd {
		t.Fatalf("SO_SNDBUF did not grow from early=%d to late=%d", earlySnd, lateSnd)
	}

	if err := ApplyTCPConnOpts(spec, srv); err != nil {
		t.Fatal(err)
	}
	if got := tcpSockoptInt(t, srv, unix.SO_SNDBUF); got < 65536 {
		t.Fatalf("accepted SO_SNDBUF=%d want >= 65536", got)
	}
}

func TestApplyTCPConnOptsAppliesSndbufLateThroughNetConnUnwrap(t *testing.T) {
	cli, _ := tcpPair(t)
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,sndbuf-late=65536")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTCPConnOpts(spec, netConnUnwrapper{Conn: cli}); err != nil {
		t.Fatal(err)
	}
	if got := tcpSockoptInt(t, cli, unix.SO_SNDBUF); got < 65536 {
		t.Fatalf("SO_SNDBUF=%d want >= 65536 through NetConn() unwrap", got)
	}
}

func TestDialTCPAllAppliesSndbufLateUnix(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	spec, err := parse.ParseSpec("TCP4:127.0.0.1:9,sndbuf-late=65536,rcvbuf-late=65536")
	if err != nil {
		t.Fatal(err)
	}
	c, err := DialTCPAll(context.Background(), "tcp4", "127.0.0.1", strconv.Itoa(port), spec, nil, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	tc, ok := c.(*net.TCPConn)
	if !ok {
		t.Fatalf("conn type %T want *net.TCPConn", c)
	}
	if got := tcpSockoptInt(t, tc, unix.SO_SNDBUF); got < 65536 {
		t.Fatalf("SO_SNDBUF=%d want >= 65536 after DialTCPAll", got)
	}
	if got := tcpSockoptInt(t, tc, unix.SO_RCVBUF); got < 65536 {
		t.Fatalf("SO_RCVBUF=%d want >= 65536 after DialTCPAll", got)
	}
}

func TestDialControlAppliesTimeosAndTTL(t *testing.T) {
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

	spec, err := parse.ParseSpec("TCP4:127.0.0.1:1,rcvtimeo=1,sndtimeo=1,ip-ttl=9,ip-tos=0x10")
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: DialControl(spec, "tcp4", nil)}
	cli, err := d.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Close() }()

	srv := (<-ch)
	if srv.err != nil {
		t.Fatal(srv.err)
	}
	defer func() { _ = srv.c.Close() }()

	tc := cli.(*net.TCPConn)
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var tv *unix.Timeval
	var ttl, tos int
	var gerr error
	_ = raw.Control(func(fd uintptr) {
		tv, gerr = unix.GetsockoptTimeval(int(fd), unix.SOL_SOCKET, unix.SO_RCVTIMEO)
		if gerr != nil {
			return
		}
		ttl, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
		if gerr != nil {
			return
		}
		tos, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS)
	})
	if gerr != nil {
		t.Fatalf("getsockopt: %v", gerr)
	}
	if tv.Sec != 1 || tv.Usec != 0 {
		t.Fatalf("SO_RCVTIMEO=%+v want 1s", tv)
	}
	if ttl != 9 {
		t.Fatalf("IP_TTL=%d want 9", ttl)
	}
	if tos != 0x10 {
		t.Fatalf("IP_TOS=%#x want %#x", tos, 0x10)
	}
}

func TestApplyUDPConnOptsAppliesLateUnix(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux SO_SNDBUF doubling")
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	uc := pc.(*net.UDPConn)

	spec, err := parse.ParseSpec("UDP-LISTEN:0,sndbuf-late=65536,rcvbuf-late=65536")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyUDPConnOpts(uc, spec, "udp"); err != nil {
		t.Fatalf("ApplyUDPConnOpts: %v", err)
	}
	if got := udpSockoptInt(t, uc, unix.SO_SNDBUF); got < 65536 {
		t.Fatalf("SO_SNDBUF=%d want >= 65536 after ApplyUDPConnOpts", got)
	}
	if got := udpSockoptInt(t, uc, unix.SO_RCVBUF); got < 65536 {
		t.Fatalf("SO_RCVBUF=%d want >= 65536 after ApplyUDPConnOpts", got)
	}
}

func TestWrapCommonAppliesLateThroughNetConnUnwrapUnix(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux SO_SNDBUF doubling")
	}
	cli, _ := tcpPair(t)
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,sndbuf-late=65536")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WrapCommon(spec, relay.NetStream{Conn: netConnUnwrapper{Conn: cli}}); err != nil {
		t.Fatalf("WrapCommon via NetConn(): %v", err)
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

// broadcastFlagOn reports whether SO_BROADCAST is enabled. Linux getsockopt
// returns 1; Darwin/BSD return the so_options bit (SO_BROADCAST is 0x20).
func broadcastFlagOn(v int) bool { return v != 0 }

func assertBroadcast(t *testing.T, got int, wantOn bool) {
	t.Helper()
	if broadcastFlagOn(got) != wantOn {
		t.Fatalf("SO_BROADCAST=%d want on=%v", got, wantOn)
	}
}

func TestApplySocketOptionsBroadcastUnix(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	if got := unixSockoptInt(t, fd, unix.SO_BROADCAST); got != 0 {
		t.Fatalf("SO_BROADCAST default=%d want 0", got)
	}

	apply := func(specText string) {
		t.Helper()
		spec, err := parse.ParseSpec(specText)
		if err != nil {
			t.Fatal(err)
		}
		if err := ApplySocketOptions(fd, spec); err != nil {
			t.Fatal(err)
		}
	}

	apply("UDP:127.0.0.1:9")
	if got := unixSockoptInt(t, fd, unix.SO_BROADCAST); got != 0 {
		t.Fatalf("absent option SO_BROADCAST=%d want 0", got)
	}

	for _, specText := range []string{
		"UDP:127.0.0.1:9,broadcast",
		"UDP:127.0.0.1:9,so-broadcast",
		"UDP:127.0.0.1:9,broadcast=1",
	} {
		apply("UDP:127.0.0.1:9,broadcast=0")
		if got := unixSockoptInt(t, fd, unix.SO_BROADCAST); got != 0 {
			t.Fatalf("after broadcast=0 SO_BROADCAST=%d want 0 (%s)", got, specText)
		}
		apply(specText)
		assertBroadcast(t, unixSockoptInt(t, fd, unix.SO_BROADCAST), true)
	}

	apply("UDP:127.0.0.1:9,broadcast=0")
	if got := unixSockoptInt(t, fd, unix.SO_BROADCAST); got != 0 {
		t.Fatalf("broadcast=0 did not clear SO_BROADCAST: got %d", got)
	}

	spec, err := parse.ParseSpec("UDP:127.0.0.1:9,broadcast=no")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, spec); err == nil {
		t.Fatal("broadcast=no: expected TYPE_INT parse error")
	}
}

func TestListenControlAppliesBroadcastUnix(t *testing.T) {
	spec, err := parse.ParseSpec("UDP-LISTEN:0,broadcast=0")
	if err != nil {
		t.Fatal(err)
	}
	lc := net.ListenConfig{Control: ListenControl(spec)}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	uc := pc.(*net.UDPConn)
	if got := udpSockoptInt(t, uc, unix.SO_BROADCAST); got != 0 {
		t.Fatalf("broadcast=0 SO_BROADCAST=%d want 0", got)
	}

	spec, err = parse.ParseSpec("UDP-LISTEN:0,so-broadcast")
	if err != nil {
		t.Fatal(err)
	}
	lc = net.ListenConfig{Control: ListenControl(spec)}
	pc, err = lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	uc = pc.(*net.UDPConn)
	assertBroadcast(t, udpSockoptInt(t, uc, unix.SO_BROADCAST), true)
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
	if err := ApplyListenOptions(fd, spec, "udp4"); err != nil {
		t.Fatal(err)
	}
	if got := unixSockoptInt(t, fd, unix.SO_BROADCAST); got != 0 {
		t.Fatalf("ApplyListenOptions applied PH_PASTSOCKET broadcast: SO_BROADCAST=%d", got)
	}
}

func TestDialControlAppliesBroadcastUnix(t *testing.T) {
	spec, err := parse.ParseSpec("UDP:127.0.0.1:9,broadcast=0")
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Control: DialControl(spec, "udp4", nil)}
	c, err := d.Dial("udp4", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	uc, ok := c.(*net.UDPConn)
	if !ok {
		t.Fatalf("conn type %T want *net.UDPConn", c)
	}
	if got := udpSockoptInt(t, uc, unix.SO_BROADCAST); got != 0 {
		t.Fatalf("UDP-CONNECT broadcast=0 SO_BROADCAST=%d want 0", got)
	}

	spec, err = parse.ParseSpec("UDP:127.0.0.1:9,broadcast")
	if err != nil {
		t.Fatal(err)
	}
	d = &net.Dialer{Control: DialControl(spec, "udp4", nil)}
	c, err = d.Dial("udp4", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	uc = c.(*net.UDPConn)
	assertBroadcast(t, udpSockoptInt(t, uc, unix.SO_BROADCAST), true)
}

func TestApplyUDPConnOptsDoesNotApplyBroadcastUnix(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	uc := pc.(*net.UDPConn)
	raw, err := uc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var setErr error
	if err := raw.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 0)
	}); err != nil {
		t.Fatal(err)
	}
	if setErr != nil {
		t.Fatal(setErr)
	}

	spec, err := parse.ParseSpec("UDP-RECV:0,broadcast=1")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyUDPConnOpts(uc, spec, "udp4"); err != nil {
		t.Fatalf("ApplyUDPConnOpts: %v", err)
	}
	if got := udpSockoptInt(t, uc, unix.SO_BROADCAST); got != 0 {
		t.Fatalf("ApplyUDPConnOpts applied PH_PASTSOCKET broadcast: SO_BROADCAST=%d", got)
	}
}
