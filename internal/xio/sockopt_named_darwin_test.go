//go:build darwin

package xio

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestApplySocketOptionsNopushNooptDarwin(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	on, err := parse.ParseSpec("TCP:127.0.0.1:9,nopush,noopt")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, on); err != nil {
		t.Fatal(err)
	}
	// XNU getsockopt(TCP_NOPUSH/TCP_NOOPT) returns tp->t_flags & TF_NOPUSH/TF_NOOPT
	// (0x1000 / 0x8), not the 0/1 value passed to setsockopt. Classic xio-tcp.c
	// only setsockopt (tag-1.8.1.3 12c08bf).
	if got := fdTCPSockoptIntDarwin(t, fd, unix.TCP_NOPUSH); !sockoptFlagOn(got) {
		t.Fatalf("TCP_NOPUSH=%d want enabled", got)
	}
	if got := fdTCPSockoptIntDarwin(t, fd, unix.TCP_NOOPT); !sockoptFlagOn(got) {
		t.Fatalf("TCP_NOOPT=%d want enabled", got)
	}

	off, err := parse.ParseSpec("TCP:127.0.0.1:9,tcp-nopush=0,tcp-noopt=0")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, off); err != nil {
		t.Fatal(err)
	}
	if got := fdTCPSockoptIntDarwin(t, fd, unix.TCP_NOPUSH); got != 0 {
		t.Fatalf("TCP_NOPUSH=%d want 0", got)
	}
	if got := fdTCPSockoptIntDarwin(t, fd, unix.TCP_NOOPT); got != 0 {
		t.Fatalf("TCP_NOOPT=%d want 0", got)
	}
}

func TestApplySocketOptionsLowWaterDarwin(t *testing.T) {
	for _, tc := range []struct {
		name, spec string
		sockType   int
		proto      int
		rcv, snd   int
	}{
		{name: "tcp", spec: "TCP:127.0.0.1:9,so-rcvlowat=512,so-sndlowat=256", sockType: unix.SOCK_STREAM, rcv: 512, snd: 256},
		{name: "udp-aliases", spec: "UDP:127.0.0.1:9,rcvlowat=64,sndlowat=32", sockType: unix.SOCK_DGRAM, proto: unix.IPPROTO_UDP, rcv: 64, snd: 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd, err := unix.Socket(unix.AF_INET, tc.sockType, tc.proto)
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
			if got := unixSockoptInt(t, fd, unix.SO_RCVLOWAT); got != tc.rcv {
				t.Fatalf("SO_RCVLOWAT=%d want %d", got, tc.rcv)
			}
			if got := unixSockoptInt(t, fd, unix.SO_SNDLOWAT); got != tc.snd {
				t.Fatalf("SO_SNDLOWAT=%d want %d", got, tc.snd)
			}
		})
	}
}

func fdTCPSockoptIntDarwin(t *testing.T, fd, opt int) int {
	t.Helper()
	v, err := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, opt)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
