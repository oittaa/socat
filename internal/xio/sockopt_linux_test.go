//go:build linux

package xio

import (
	"errors"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func skipIfUnprivilegedBindToDevice(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skip(err)
	}
}

func TestApplySocketOptionsBindToDeviceLinux(t *testing.T) {
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
	skipIfUnprivilegedBindToDevice(t, err)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unix.GetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimRight(got, "\x00") != "lo" {
		t.Fatalf("SO_BINDTODEVICE=%q want lo", got)
	}
}

func TestApplySocketOptionsBindToDeviceIfAliasLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	spec, err := parse.ParseSpec("UDP:127.0.0.1:9,if=lo")
	if err != nil {
		t.Fatal(err)
	}
	if spec.OptionValue("bindtodevice", "") != "lo" {
		t.Fatalf("if= did not canonicalize to bindtodevice: %#v", spec.Options)
	}
	err = ApplySocketOptions(fd, spec)
	skipIfUnprivilegedBindToDevice(t, err)
	if err != nil {
		t.Fatal(err)
	}
}

func TestApplySocketOptionsBindToDeviceInvalidLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	spec, err := parse.ParseSpec("UDP:127.0.0.1:9,bindtodevice=socat-no-such-iface")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplySocketOptions(fd, spec)
	if err == nil {
		t.Fatal("invalid interface name succeeded")
	}
	skipIfUnprivilegedBindToDevice(t, err)
}
