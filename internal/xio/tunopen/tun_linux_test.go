//go:build linux

package tunopen

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

var _ syscall.Conn = (*packetRawStream)(nil)

func TestHtons(t *testing.T) {
	// ETH_P_ALL is 0x0003; sockaddr_ll.Protocol is network byte order.
	got := htons(unix.ETH_P_ALL)
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], got)
	if binary.BigEndian.Uint16(b[:]) != unix.ETH_P_ALL {
		t.Fatalf("htons(%#x)=%#x is not network order", unix.ETH_P_ALL, got)
	}
}

func TestIsTunIPv6Multicast(t *testing.T) {
	// PI header + IPv6 dest ff02::1
	withPI := make([]byte, 4+40)
	binary.BigEndian.PutUint16(withPI[2:4], unix.ETH_P_IPV6)
	withPI[4+24] = 0xff
	if !isTunIPv6Multicast(withPI, false) {
		t.Fatal("PI IPv6 multicast not detected")
	}

	withPI[4+24] = 0xfe // unicast-ish
	if isTunIPv6Multicast(withPI, false) {
		t.Fatal("PI IPv6 unicast treated as multicast")
	}

	// IPv4 proto in PI
	ipv4 := make([]byte, 4+20)
	binary.BigEndian.PutUint16(ipv4[2:4], unix.ETH_P_IP)
	if isTunIPv6Multicast(ipv4, false) {
		t.Fatal("IPv4 PI treated as IPv6 multicast")
	}

	noPI := make([]byte, 40)
	noPI[0] = 0x60
	noPI[24] = 0xff
	if !isTunIPv6Multicast(noPI, true) {
		t.Fatal("no-PI IPv6 multicast not detected")
	}

	if isTunIPv6Multicast([]byte("hello"), false) {
		t.Fatal("short payload treated as multicast")
	}
}

func TestTunPositional(t *testing.T) {
	s, err := parse.ParseSpec("TUN:10.1.2.3/24")
	if err != nil {
		t.Fatal(err)
	}
	got, err := tunPositional(s)
	if err != nil || got != "10.1.2.3/24" {
		t.Fatalf("got %q err=%v", got, err)
	}

	s, err = parse.ParseSpec("TUN:::::")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tunPositional(s); err == nil {
		t.Fatal("TUN::::: should fail")
	}

	s, err = parse.ParseSpec("TUN")
	if err != nil {
		t.Fatal(err)
	}
	got, err = tunPositional(s)
	if err != nil || got != "" {
		t.Fatalf("empty TUN: got %q err=%v", got, err)
	}
}

func TestTUNRejectsBadName(t *testing.T) {
	s, err := parse.ParseSpec("TUN,tun-name=../all")
	if err != nil {
		t.Fatal(err)
	}
	_, err = openTUN(context.Background(), s, xio.ModeRDWR, nil)
	if err == nil {
		t.Fatal("expected tun-name ../all to fail")
	}
}

func TestValidIfaceName(t *testing.T) {
	ok := []string{"eth0", "tun0", "scattun0", "br-abc", "dummy0"}
	for _, n := range ok {
		if !validIfaceName(n) {
			t.Fatalf("%q should be valid", n)
		}
	}
	bad := []string{"", ".", "..", "a/b", "../all", "x\x00y", "/dev/tun"}
	for _, n := range bad {
		if validIfaceName(n) {
			t.Fatalf("%q should be invalid", n)
		}
	}
}

func TestParseIffOpts(t *testing.T) {
	s, err := parse.ParseSpec("TUN,iff-up,iff-noarp=0")
	if err != nil {
		t.Fatal(err)
	}
	set, clear := parseIffOpts(s)
	if set&unix.IFF_UP == 0 {
		t.Fatal("iff-up not set")
	}
	if clear&unix.IFF_NOARP == 0 {
		t.Fatal("iff-noarp=0 not cleared")
	}
}

func TestParseIffOptsRemainingClassicFlags(t *testing.T) {
	s, err := parse.ParseSpec("TUN,iff-notrailers,master,iff-slave=1,portsel=0,automedia")
	if err != nil {
		t.Fatal(err)
	}
	set, clear := parseIffOpts(s)
	for name, bit := range map[string]uint16{
		"iff-notrailers": unix.IFF_NOTRAILERS,
		"master":         unix.IFF_MASTER,
		"iff-slave":      unix.IFF_SLAVE,
		"automedia":      unix.IFF_AUTOMEDIA,
	} {
		if set&bit == 0 {
			t.Errorf("%s not set in 0x%x", name, set)
		}
	}
	if clear&unix.IFF_PORTSEL == 0 {
		t.Fatal("portsel=0 not cleared")
	}
	if set&unix.IFF_PORTSEL != 0 {
		t.Fatal("portsel=0 must not also set IFF_PORTSEL")
	}
}

func TestTUNOpenStaysAlive(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("need root for TUN")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("/dev/net/tun not available")
	}

	s, err := parse.ParseSpec("TUN:10.255.254.1/24,iff-up=1,tun-type=tun,tun-name=scattun0,if-mtu=888")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openTUN(context.Background(), s, xio.ModeRDWR, nil)
	if err != nil {
		t.Skipf("open TUN: %v", err)
	}
	defer func() { _ = o.Close() }()

	errc := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		_, err := o.Stream.Read(buf)
		errc <- err
	}()
	select {
	case err := <-errc:
		if err != nil && strings.Contains(err.Error(), "not pollable") {
			t.Fatalf("TUN Read failed with netpoll error: %v", err)
		}
		if err != nil && !errors.Is(err, unix.EBADF) {
			t.Fatalf("TUN Read returned immediately: %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		// blocked in Read: the Go netpoller is not involved
	}
}

func TestInterfaceSyscallConnAndConnectedOnceLinux(t *testing.T) {
	spec, err := parse.ParseSpec(fmt.Sprintf("INTERFACE:lo,setsockopt-int=%d:%d:1", unix.SOL_SOCKET, unix.SO_KEEPALIVE))
	if err != nil {
		t.Fatal(err)
	}
	var n int
	restore := xio.SetSockoptTestHook(func(c xio.SockoptCall) {
		if c.Opt == unix.SO_KEEPALIVE {
			n++
		}
	})
	defer restore()
	o, err := openINTERFACE(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	st, ok := o.Stream.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		// WrapCommon may wrap the stream (timeouts, crnl, …).
		if n != 1 {
			t.Fatalf("SO_KEEPALIVE setsockopt count=%d want 1", n)
		}
		return
	}
	raw, err := st.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got int
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		got, gerr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_KEEPALIVE)
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	if got == 0 {
		t.Fatalf("SO_KEEPALIVE=%d want enabled", got)
	}
	if n != 1 {
		t.Fatalf("SO_KEEPALIVE setsockopt count=%d want 1", n)
	}
}
