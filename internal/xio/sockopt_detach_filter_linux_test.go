//go:build linux

package xio

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestApplySocketOptionsDetachFilterLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	spec, err := parse.ParseSpec("UDP:127.0.0.1:9,so-detach-filter")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplySocketOptions(fd, spec)
	if err == nil || !errors.Is(err, unix.ENOENT) {
		t.Fatalf("detach with no filter: err=%v want ENOENT", err)
	}

	filter := []unix.SockFilter{{Code: unix.BPF_RET | unix.BPF_K, K: ^uint32(0)}}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("SO_ATTACH_FILTER: %v", err)
		}
		t.Fatal(err)
	}
	runtime.KeepAlive(filter)

	spec, err = parse.ParseSpec("UDP:127.0.0.1:9,detachfilter=1")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, spec); err != nil {
		t.Fatal(err)
	}
	err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DETACH_FILTER, 0)
	if err == nil || !errors.Is(err, unix.ENOENT) {
		t.Fatalf("second detach: err=%v want ENOENT", err)
	}
}

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
	err = ApplySocketOptions(fd, spec)
	if err == nil || !strings.Contains(err.Error(), "invalid value") {
		t.Fatalf("err=%v want invalid value", err)
	}
}
