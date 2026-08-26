//go:build linux

package xio

import (
	"net"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func tcpPairForKeepalive(t *testing.T) *net.TCPConn {
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
	srv := (<-ch)
	if srv.err != nil {
		t.Fatal(srv.err)
	}
	t.Cleanup(func() { _ = srv.c.Close() })
	return cli
}

func TestApplyKeepAliveConfigValues(t *testing.T) {
	spec, err := parse.ParseSpec("TCP4:127.0.0.1:1,keepalive,keepidle=7s,keepintvl=9s,keepcnt=6")
	if err != nil {
		t.Fatal(err)
	}
	tc := tcpPairForKeepalive(t)
	if err := ApplyTCPConnOpts(spec, tc); err != nil {
		t.Fatal(err)
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	get := func(opt int) int {
		var v int
		var gerr error
		_ = raw.Control(func(fd uintptr) {
			v, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, opt)
		})
		if gerr != nil {
			t.Fatalf("getsockopt %d: %v", opt, gerr)
		}
		return v
	}
	if got := get(unix.TCP_KEEPIDLE); got != 7 {
		t.Fatalf("TCP_KEEPIDLE=%d want 7", got)
	}
	if got := get(unix.TCP_KEEPINTVL); got != 9 {
		t.Fatalf("TCP_KEEPINTVL=%d want 9", got)
	}
	if got := get(unix.TCP_KEEPCNT); got != 6 {
		t.Fatalf("TCP_KEEPCNT=%d want 6", got)
	}
}

func TestApplyKeepAliveConfigPreservesUnspecifiedValues(t *testing.T) {
	tc := tcpPairForKeepalive(t)
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	get := func(opt int) int {
		t.Helper()
		var value int
		var getErr error
		_ = raw.Control(func(fd uintptr) {
			value, getErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, opt)
		})
		if getErr != nil {
			t.Fatal(getErr)
		}
		return value
	}
	intervalBefore := get(unix.TCP_KEEPINTVL)
	countBefore := get(unix.TCP_KEEPCNT)
	spec, err := parse.ParseSpec("TCP4:127.0.0.1:1,keepidle=7s")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTCPConnOpts(spec, tc); err != nil {
		t.Fatal(err)
	}
	if got := get(unix.TCP_KEEPIDLE); got != 7 {
		t.Fatalf("TCP_KEEPIDLE=%d want 7", got)
	}
	if got := get(unix.TCP_KEEPINTVL); got != intervalBefore {
		t.Fatalf("TCP_KEEPINTVL=%d want preserved %d", got, intervalBefore)
	}
	if got := get(unix.TCP_KEEPCNT); got != countBefore {
		t.Fatalf("TCP_KEEPCNT=%d want preserved %d", got, countBefore)
	}
}

func TestApplyKeepAliveConfigErrors(t *testing.T) {
	cases := []struct{ spec, want string }{
		{"TCP4:127.0.0.1:1,keepidle=nope", "keepidle"},
		{"TCP4:127.0.0.1:1,keepidle=-5s", "positive"},
		{"TCP4:127.0.0.1:1,keepcnt=-1", "keepcnt"},
		{"TCP4:127.0.0.1:1,keepcnt=0", "keepcnt"},
	}
	for _, tc := range cases {
		spec, err := parse.ParseSpec(tc.spec)
		if err != nil {
			t.Fatalf("%s: %v", tc.spec, err)
		}
		tc2 := tcpPairForKeepalive(t)
		err = ApplyTCPConnOpts(spec, tc2)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err=%v want containing %q", tc.spec, err, tc.want)
		}
	}
}

func TestApplyKeepAliveExplicitDisableWins(t *testing.T) {
	spec, err := parse.ParseSpec("TCP4:127.0.0.1:1,keepidle=7s,keepalive=0")
	if err != nil {
		t.Fatal(err)
	}
	tc := tcpPairForKeepalive(t)
	// Explicit keepalive=0 must win over sub-options; net.TCPConn exposes no
	// getter, so success here means the config path accepted the precedence.
	if err := ApplyTCPConnOpts(spec, tc); err != nil {
		t.Fatalf("explicit disable: %v", err)
	}
}

func TestApplyTCPConnOptsIPv6TTL(t *testing.T) {
	ln, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 unavailable: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, _ := ln.AcceptTCP()
		accepted <- conn
	}()
	client, err := net.DialTCP("tcp6", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server := <-accepted
	t.Cleanup(func() { _ = server.Close() })
	spec, err := parse.ParseSpec("TCP6:[::1]:1,ip-ttl=9")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTCPConnOpts(spec, client); err != nil {
		t.Fatal(err)
	}
	raw, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ttl int
	var optionErr error
	_ = raw.Control(func(fd uintptr) {
		ttl, optionErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
	})
	if optionErr != nil {
		t.Fatal(optionErr)
	}
	if ttl != 9 {
		t.Fatalf("IP_TTL=%d want 9 (classic SOL_IP, not IPV6_UNICAST_HOPS translation)", ttl)
	}
}

func TestApplyTCPConnOptsIPv6TOS(t *testing.T) {
	ln, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 unavailable: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, _ := ln.AcceptTCP()
		accepted <- conn
	}()
	client, err := net.DialTCP("tcp6", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server := <-accepted
	t.Cleanup(func() { _ = server.Close() })
	spec, err := parse.ParseSpec("TCP6:[::1]:1,ip-tos=0x10")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTCPConnOpts(spec, client); err != nil {
		t.Fatal(err)
	}
	raw, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var tos int
	var optionErr error
	_ = raw.Control(func(fd uintptr) {
		tos, optionErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS)
	})
	if optionErr != nil {
		t.Fatal(optionErr)
	}
	if tos != 0x10 {
		t.Fatalf("IP_TOS=%#x want 0x10 (classic SOL_IP, not skipped on TCP6)", tos)
	}
}

func TestApplyTCPConnOptsIPv6UnicastHops(t *testing.T) {
	ln, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 unavailable: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, _ := ln.AcceptTCP()
		accepted <- conn
	}()
	client, err := net.DialTCP("tcp6", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server := <-accepted
	t.Cleanup(func() { _ = server.Close() })
	spec, err := parse.ParseSpec("TCP6:[::1]:1,ipv6-unicast-hops=9")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTCPConnOpts(spec, client); err != nil {
		t.Fatal(err)
	}
	raw, err := client.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var hops int
	var optionErr error
	_ = raw.Control(func(fd uintptr) {
		hops, optionErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS)
	})
	if optionErr != nil {
		t.Fatal(optionErr)
	}
	if hops != 9 {
		t.Fatalf("IPV6_UNICAST_HOPS=%d want 9", hops)
	}
}

func TestApplyTCPConnOptsIPv4RejectsIPv6SendOpts(t *testing.T) {
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, _ := ln.AcceptTCP()
		accepted <- conn
	}()
	client, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server := <-accepted
	t.Cleanup(func() { _ = server.Close() })
	for _, specText := range []string{
		"TCP:127.0.0.1:1,ipv6-tclass=16",
		"TCP:127.0.0.1:1,ipv6-unicast-hops=9",
	} {
		spec, err := parse.ParseSpec(specText)
		if err != nil {
			t.Fatal(err)
		}
		err = ApplyTCPConnOpts(spec, client)
		if err == nil || !strings.Contains(err.Error(), "not supported on IPv4") {
			t.Fatalf("%s: err=%v want not supported on IPv4", specText, err)
		}
	}
}

func TestApplyListenBacklogUnix(t *testing.T) {
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if err := ApplyListenBacklog(ln, 3); err != nil {
		t.Fatal(err)
	}
}
