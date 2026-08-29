//go:build unix

package xio

import (
	"os"
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
	if got := ownerIoctlGet(t, fd, ownerIoctlFIOGETOWN); got != pid {
		t.Fatalf("FIOGETOWN=%d want %d", got, pid)
	}

	spec, err = parse.ParseSpec("TCP:127.0.0.1:9,siocspgrp=" + strconv.Itoa(pid))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, spec); err != nil {
		t.Fatal(err)
	}
	if got := ownerIoctlGet(t, fd, uint(unix.SIOCGPGRP)); got != pid {
		t.Fatalf("SIOCGPGRP=%d want %d", got, pid)
	}

	spec, err = parse.ParseSpec("TCP:127.0.0.1:9,fiosetown")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, spec); err != nil {
		t.Fatal(err)
	}
	if got := ownerIoctlGet(t, fd, ownerIoctlFIOGETOWN); got != 1 {
		t.Fatalf("bare fiosetown FIOGETOWN=%d want 1", got)
	}
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
	if got := ownerIoctlGet(t, fd, uint(unix.SIOCGPGRP)); got != pid {
		t.Fatalf("last siocspgrp SIOCGPGRP=%d want %d", got, pid)
	}
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

func ownerIoctlGet(t *testing.T, fd int, req uint) int {
	t.Helper()
	v, err := unix.IoctlGetInt(fd, req)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
