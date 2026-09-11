//go:build darwin

package xio

import (
	"errors"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestLinuxOnlyNamedTCPUnsupportedOnDarwin(t *testing.T) {
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
			t.Fatalf("%s: %v want %v", opt, err, errNamedOptUnsupported)
		}
	}
}
