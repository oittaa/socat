//go:build linux

package xio

import (
	"errors"
	"fmt"
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

func TestLookupNamedPastSocketIntSCTPLinux(t *testing.T) {
	level, opt, ok, err := lookupNamedPastSocketInt("sctp-nodelay")
	if err != nil || !ok || level != solSCTP || opt != sctpNodelay {
		t.Fatalf("sctp-nodelay lookup level=%d opt=%d ok=%v err=%v want SOL_SCTP/%d", level, opt, ok, err, sctpNodelay)
	}
	if level == unix.IPPROTO_TCP || opt == unix.TCP_NODELAY {
		t.Fatal("sctp-nodelay must not reuse TCP_NODELAY")
	}
	level, opt, ok, err = lookupNamedPastSocketInt("sctp-maxseg")
	if err != nil || !ok || level != solSCTP || opt != sctpMaxseg {
		t.Fatalf("sctp-maxseg lookup level=%d opt=%d ok=%v err=%v want SOL_SCTP/%d", level, opt, ok, err, sctpMaxseg)
	}
	_, _, ok, err = lookupNamedPastSocketInt("sctp-maxseg-late")
	if ok || err != nil {
		t.Fatalf("sctp-maxseg-late PASTSOCKET lookup ok=%v err=%v; must stay unimplemented", ok, err)
	}
	_, _, ok, err = lookupNamedConnectedInt("sctp-maxseg-late")
	if ok || err != nil {
		t.Fatalf("sctp-maxseg-late CONNECTED lookup ok=%v err=%v; must stay unimplemented", ok, err)
	}
}

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

func TestApplySocketOptionsBareSCTPNodelayLinux(t *testing.T) {
	fd := openSCTPStream(t)
	spec, err := parse.ParseSpec("SCTP4:127.0.0.1:9,sctp-nodelay")
	if err != nil {
		t.Fatal(err)
	}
	var sawTCP bool
	restore := SetSockoptTestHook(func(c SockoptCall) {
		if c.Level == unix.IPPROTO_TCP && c.Opt == unix.TCP_NODELAY {
			sawTCP = true
		}
	})
	t.Cleanup(restore)
	if err := ApplySocketOptions(fd, spec); err != nil {
		t.Fatal(err)
	}
	if sawTCP {
		t.Fatal("sctp-nodelay must not call TCP_NODELAY")
	}
	if got := fdSCTPSockoptInt(t, fd, sctpNodelay); got != 1 {
		t.Fatalf("SCTP_NODELAY=%d want 1 after bare sctp-nodelay", got)
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

func TestPastSocketSCTPNamedAndGenericCommandLineOrderLinux(t *testing.T) {
	fd := openSCTPStream(t)
	for _, tc := range []struct {
		name    string
		options string
		want    []int
	}{
		{
			name:    "named-then-generic",
			options: fmt.Sprintf("sctp-nodelay=1,setsockopt-socket=%d:%d:0", solSCTP, sctpNodelay),
			want:    []int{1, 0},
		},
		{
			name:    "generic-then-named",
			options: fmt.Sprintf("setsockopt-socket=%d:%d:0,sctp-nodelay=1", solSCTP, sctpNodelay),
			want:    []int{0, 1},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := parse.ParseSpec("SCTP4:127.0.0.1:9," + tc.options)
			if err != nil {
				t.Fatal(err)
			}
			var got []int
			restore := SetSockoptTestHook(func(call SockoptCall) {
				if call.Level == solSCTP && call.Opt == sctpNodelay {
					got = append(got, call.IntValue)
				}
			})
			t.Cleanup(restore)
			if err := ApplySocketOptions(fd, spec); err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("SCTP_NODELAY values=%v want %v", got, tc.want)
			}
		})
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
