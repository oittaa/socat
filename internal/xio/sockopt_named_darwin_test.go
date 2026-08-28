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

func fdTCPSockoptIntDarwin(t *testing.T, fd, opt int) int {
	t.Helper()
	v, err := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, opt)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
