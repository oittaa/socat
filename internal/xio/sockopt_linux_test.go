//go:build linux

package xio

import (
	"errors"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
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
	err = ApplySocketOptions(fd, mustDecodeAddress(t, spec))
	skipIfUnprivilegedBindToDevice(t, err)
	if err != nil {
		t.Fatal(err)
	}
}

func TestApplySocketOptionsBindToDeviceInterfaceAliasLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	spec, err := parse.ParseSpec("UDP:127.0.0.1:9,interface=lo")
	if err != nil {
		t.Fatal(err)
	}
	if spec.OptionValue("bindtodevice", "") != "lo" {
		t.Fatalf("interface= did not canonicalize to bindtodevice: %#v", spec.Options)
	}
	err = ApplySocketOptions(fd, mustDecodeAddress(t, spec))
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
	err = ApplySocketOptions(fd, mustDecodeAddress(t, spec))
	if err == nil {
		t.Fatal("invalid interface name succeeded")
	}
	skipIfUnprivilegedBindToDevice(t, err)
}

func TestSetupStreamAppliesLateThroughNetConnUnwrap(t *testing.T) {
	cli, _ := tcpPair(t)
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,sndbuf-late=65536")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SetupStream(mustDecodeAddress(t, spec), relay.NetStream{Conn: netConnUnwrapper{Conn: cli}}); err != nil {
		t.Fatalf("SetupStream via NetConn(): %v", err)
	}
	if got := tcpSockoptInt(t, cli, unix.SO_SNDBUF); got < 65536 {
		t.Fatalf("SO_SNDBUF=%d want >= 65536 through NetConn() unwrap", got)
	}
}
