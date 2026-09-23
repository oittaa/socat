//go:build linux

package sockopt

import (
	"errors"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

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
		err = ApplySocketOptions(fd, mustDecodeAddress(t, spec))
		if err == nil || !errors.Is(err, errNamedOptUnsupported) {
			t.Fatalf("%s on Linux: %v want %v", opt, err, errNamedOptUnsupported)
		}
	}
}
