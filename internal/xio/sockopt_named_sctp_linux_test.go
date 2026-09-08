//go:build linux

package xio

import (
	"errors"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func skipIfNoSCTP(t *testing.T) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_SCTP)
	if err != nil {
		t.Skipf("SCTP unavailable: %v", err)
	}
	_ = unix.Close(fd)
}

func openSCTPStream(t *testing.T) int {
	t.Helper()
	skipIfNoSCTP(t)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_SCTP)
	if err != nil {
		t.Skipf("SCTP unavailable: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

func fdSCTPSockoptInt(t *testing.T, fd, opt int) int {
	t.Helper()
	v, err := unix.GetsockoptInt(fd, solSCTP, opt)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

type ctrlFD int

func (fd ctrlFD) Control(f func(uintptr)) error {
	f(uintptr(fd))
	return nil
}

func (fd ctrlFD) Read(func(uintptr) bool) error  { return syscall.EINVAL }
func (fd ctrlFD) Write(func(uintptr) bool) error { return syscall.EINVAL }

func TestApplySocketOptionsSCTPNodelayOnTCPLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	spec, err := parse.ParseSpec("TCP:127.0.0.1:9,sctp-nodelay")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplySocketOptions(fd, spec)
	if err == nil {
		t.Fatal("sctp-nodelay on TCP must fail, not no-op")
	}
	if !errors.Is(err, unix.ENOPROTOOPT) && !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.EPROTONOSUPPORT) {
		t.Fatalf("sctp-nodelay on TCP error=%v want ENOPROTOOPT/EOPNOTSUPP/EPROTONOSUPPORT", err)
	}
}

func TestApplySocketOptionsSCTPMaxsegOnUDPLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	spec, err := parse.ParseSpec("UDP:127.0.0.1:9,sctp-maxseg=1400")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplySocketOptions(fd, spec)
	if err == nil {
		t.Fatal("sctp-maxseg on UDP must fail, not no-op")
	}
	if !errors.Is(err, unix.ENOPROTOOPT) && !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.EPROTONOSUPPORT) {
		t.Fatalf("sctp-maxseg on UDP error=%v want ENOPROTOOPT/EOPNOTSUPP/EPROTONOSUPPORT", err)
	}
}

func TestApplySocketOptionsRejectsInvalidSCTPNodelayLinux(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	spec, err := parse.ParseSpec("SCTP:127.0.0.1:9,sctp-nodelay=no")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, spec); err == nil {
		t.Fatal("sctp-nodelay=no must fail (TYPE_INT), not no-op")
	}
}

func TestApplySocketOptionsSCTPMaxsegLinux(t *testing.T) {
	fd := openSCTPStream(t)
	spec, err := parse.ParseSpec("SCTP4:127.0.0.1:9,sctp-maxseg=1400")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, spec); err != nil {
		t.Fatal(err)
	}
	if got := fdSCTPSockoptInt(t, fd, sctpMaxseg); got != 1400 {
		t.Fatalf("SCTP_MAXSEG=%d want 1400", got)
	}
}

func TestApplySocketOptionsSCTPNodelayClearLinux(t *testing.T) {
	fd := openSCTPStream(t)
	on, err := parse.ParseSpec("SCTP4:127.0.0.1:9,sctp-nodelay")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, on); err != nil {
		t.Fatal(err)
	}
	off, err := parse.ParseSpec("SCTP4:127.0.0.1:9,sctp-nodelay=0")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplySocketOptions(fd, off); err != nil {
		t.Fatal(err)
	}
	if got := fdSCTPSockoptInt(t, fd, sctpNodelay); got != 0 {
		t.Fatalf("sctp-nodelay=0 SCTP_NODELAY=%d want 0", got)
	}
}

func TestListenControlAppliesSCTPNodelayLinux(t *testing.T) {
	fd := openSCTPStream(t)
	spec, err := parse.ParseSpec("SCTP4-LISTEN:0,sctp-nodelay,sctp-maxseg=1400")
	if err != nil {
		t.Fatal(err)
	}
	if err := ListenControl(spec)("sctp4", "127.0.0.1:0", ctrlFD(fd)); err != nil {
		t.Fatal(err)
	}
	if got := fdSCTPSockoptInt(t, fd, sctpNodelay); got != 1 {
		t.Fatalf("ListenControl SCTP_NODELAY=%d want 1", got)
	}
	if got := fdSCTPSockoptInt(t, fd, sctpMaxseg); got != 1400 {
		t.Fatalf("ListenControl SCTP_MAXSEG=%d want 1400", got)
	}
}

func TestDialControlAppliesSCTPNodelayLinux(t *testing.T) {
	fd := openSCTPStream(t)
	spec, err := parse.ParseSpec("SCTP4:127.0.0.1:9,sctp-nodelay")
	if err != nil {
		t.Fatal(err)
	}
	if err := DialControl(spec, "sctp4", nil)("sctp4", "127.0.0.1:9", ctrlFD(fd)); err != nil {
		t.Fatal(err)
	}
	if got := fdSCTPSockoptInt(t, fd, sctpNodelay); got != 1 {
		t.Fatalf("DialControl SCTP_NODELAY=%d want 1", got)
	}
}
