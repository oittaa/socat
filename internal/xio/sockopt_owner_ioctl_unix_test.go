//go:build linux || darwin

package xio

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

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
	if err := ApplySocketOptions(fd, mustDecodeAddress(t, spec)); err != nil {
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
		config, err := decodeAddress(spec)
		if err == nil {
			err = ApplySocketOptions(fd, config)
		}
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
	assertFIOGETOWN(t, fd, want)
}

func ownerIoctlGet(t *testing.T, fd int, req uint) int {
	t.Helper()
	v, err := unix.IoctlGetInt(fd, req)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
