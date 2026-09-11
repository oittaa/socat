//go:build linux

package xio

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestApplySocketOptionsDetachFilterInvalidLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	spec, err := parse.ParseSpec("UDP:127.0.0.1:9,so-detach-filter=no")
	if err != nil {
		t.Fatal(err)
	}
	config, err := decodeAddress(spec)
	if err == nil {
		err = ApplySocketOptions(fd, config)
	}
	if err == nil || !strings.Contains(err.Error(), "invalid value") {
		t.Fatalf("err=%v want invalid value", err)
	}
}
