//go:build unix && !linux && !darwin

package xio

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestApplySocketOptionsLowWaterUnixOther(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,so-rcvlowat=64,so-sndlowat=32")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, spec); err != nil {
		t.Fatal(err)
	}
	if got := unixSockoptInt(t, fd, unix.SO_RCVLOWAT); got != 64 {
		t.Fatalf("SO_RCVLOWAT=%d want 64", got)
	}
	if got := unixSockoptInt(t, fd, unix.SO_SNDLOWAT); got != 32 {
		t.Fatalf("SO_SNDLOWAT=%d want 32", got)
	}
}
