//go:build unix

package xio

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestApplySocketOptionsOwnerIoctlUnix(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	pid := os.Getpid()

	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,fiosetown=" + strconv.Itoa(pid))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, spec); err != nil {
		t.Fatal(err)
	}
	assertSocketOwner(t, fd, pid)

	spec, err = parse.ParseSpec("TCP:127.0.0.1:9,siocspgrp=" + strconv.Itoa(pid))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, spec); err != nil {
		t.Fatal(err)
	}
	assertSocketOwner(t, fd, pid)

	spec, err = parse.ParseSpec("TCP:127.0.0.1:9,fiosetown")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, spec); err != nil {
		t.Fatal(err)
	}
	assertSocketOwner(t, fd, 1)
}

func TestApplySocketOptionsOwnerIoctlCommandLineOrderUnix(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	pid := os.Getpid()
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,fiosetown=1,siocspgrp=" + strconv.Itoa(pid))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, spec); err != nil {
		t.Fatal(err)
	}
	assertSocketOwner(t, fd, pid)
}

func TestApplySocketOptionsOwnerIoctlInvalidUnix(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	for _, specText := range []string{
		"TCP:127.0.0.1:9,fiosetown=no",
		"TCP:127.0.0.1:9,siocspgrp=4294967296",
	} {
		spec, err := parse.ParseSpec(specText)
		if err != nil {
			t.Fatal(err)
		}
		err = ApplySocketOptions(fd, spec)
		if err == nil || !strings.Contains(err.Error(), "invalid value") {
			t.Fatalf("%s: err=%v want invalid value", specText, err)
		}
	}
}

func assertSocketOwner(t *testing.T, fd, want int) {
	t.Helper()
	got, err := unix.FcntlInt(uintptr(fd), unix.F_GETOWN, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("F_GETOWN=%d want %d", got, want)
	}
	if got := ownerIoctlGet(t, fd, uint(unix.SIOCGPGRP)); got != want {
		t.Fatalf("SIOCGPGRP=%d want %d", got, want)
	}
	if runtime.GOOS == "darwin" {
		// FIOGETOWN SET works; GET does not copy out (see
		// sockopt_owner_ioctl_bsd.go). Verify with F_GETOWN / SIOCGPGRP.
		return
	}
	if got := ownerIoctlGet(t, fd, ownerIoctlFIOGETOWN); got != want {
		t.Fatalf("FIOGETOWN=%d want %d", got, want)
	}
}

func ownerIoctlGet(t *testing.T, fd int, req uint) int {
	t.Helper()
	v, err := unix.IoctlGetInt(fd, req)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
