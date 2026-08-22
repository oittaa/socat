//go:build unix

package xio

import (
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
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

	apply("UDP:127.0.0.1:9,rcvtimeo=1.25,sndtimeo=2.5", 1250*time.Millisecond, 2500*time.Millisecond)
	apply("UDP:127.0.0.1:9,rcvtimeo=0,sndtimeo=0", 0, 0)
}

func TestTimevalFromSpecRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{"-1", "banana", "NaN", "1e100"} {
		if _, err := timevalFromSpec(value); err == nil {
			t.Errorf("timevalFromSpec(%q) succeeded", value)
		}
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
