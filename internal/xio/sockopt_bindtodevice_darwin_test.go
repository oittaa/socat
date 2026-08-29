//go:build darwin

package xio

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestBindToDeviceUnsupportedOffLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	spec, err := parse.ParseSpec("UDP:127.0.0.1:9,bindtodevice=lo")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplySocketOptions(fd, spec)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("error=%v want not supported", err)
	}
}
