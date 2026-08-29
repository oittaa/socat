//go:build linux

package xio

import (
	"net"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestLinuxIPv6RecvExtSetsockopt(t *testing.T) {
	spec, err := parse.ParseSpec("UDP6:[::1]:1,ipv6-recvdstopts,recvhopopts=1,ipv6-recvrthdr,ipv6-recvpathmtu=1")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	raw, err := pc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		optionErr = ApplyAncillaryRecvOpts(int(fd), spec)
	}); err != nil {
		t.Fatal(err)
	}
	if optionErr != nil {
		t.Fatal(optionErr)
	}
	want := []struct {
		name string
		opt  int
	}{
		{"IPV6_RECVDSTOPTS", unix.IPV6_RECVDSTOPTS},
		{"IPV6_RECVHOPOPTS", unix.IPV6_RECVHOPOPTS},
		{"IPV6_RECVRTHDR", unix.IPV6_RECVRTHDR},
		{"IPV6_RECVPATHMTU", unix.IPV6_RECVPATHMTU},
	}
	var gerr error
	_ = raw.Control(func(fd uintptr) {
		for _, o := range want {
			got, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, o.opt)
			if err != nil {
				gerr = err
				return
			}
			if got == 0 {
				t.Errorf("%s=%d want enabled", o.name, got)
			}
		}
	})
	if gerr != nil {
		t.Fatal(gerr)
	}
}

func TestLinuxIPv6RecvExtLastOccurrence(t *testing.T) {
	spec, err := parse.ParseSpec("UDP6:[::1]:1,ipv6-recvdstopts=1,recvdstopts=0")
	if err != nil {
		t.Fatal(err)
	}
	if NeedAncillary(spec) {
		t.Fatal("last recvdstopts=0 must disable ReadMsg")
	}
	pc, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	calls := collectSetSockopt(t)
	raw, err := pc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		optionErr = ApplyAncillaryRecvOpts(int(fd), spec)
	}); err != nil {
		t.Fatal(err)
	}
	if optionErr != nil {
		t.Fatal(optionErr)
	}
	n := countLevelOpt(calls.snapshot(), unix.IPPROTO_IPV6, unix.IPV6_RECVDSTOPTS)
	if n != 2 {
		t.Fatalf("IPV6_RECVDSTOPTS setsockopt count=%d want 2", n)
	}
	var got int
	var gerr error
	_ = raw.Control(func(fd uintptr) {
		got, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVDSTOPTS)
	})
	if gerr != nil {
		t.Fatal(gerr)
	}
	if got != 0 {
		t.Fatalf("IPV6_RECVDSTOPTS=%d want 0 (last occurrence)", got)
	}
}

func TestLinuxIPv6BlobIntSetsockoptRejected(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	opts := []struct {
		name string
		opt  int
	}{
		{"IPV6_DSTOPTS", unix.IPV6_DSTOPTS},
		{"IPV6_HOPOPTS", unix.IPV6_HOPOPTS},
		{"IPV6_RTHDR", unix.IPV6_RTHDR},
		{"IPV6_HOPLIMIT", unix.IPV6_HOPLIMIT},
		{"IPV6_PKTINFO", unix.IPV6_PKTINFO},
		{"IPV6_AUTHHDR", unix.IPV6_AUTHHDR},
	}
	for _, o := range opts {
		err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, o.opt, 1)
		if err == nil {
			t.Errorf("%s int setsockopt succeeded; do not classify as an unimplementable blob without implementing it", o.name)
		}
	}
}
