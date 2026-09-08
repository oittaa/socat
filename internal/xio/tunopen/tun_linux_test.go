//go:build linux

package tunopen

import (
	"context"
	"encoding/binary"
	"strings"
	"syscall"
	"testing"

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

func TestPacketAuxVLANTCIEmpty(t *testing.T) {
	if tci, ok := packetAuxVLANTCI(nil); ok || tci != 0 {
		t.Fatalf("empty oob: tci=%d ok=%v", tci, ok)
	}
	n, err := restoreVLANFromAuxdata(make([]byte, 64), 20, nil)
	if err != nil || n != 20 {
		t.Fatalf("empty auxdata n=%d err=%v", n, err)
	}
}

func TestTUNRetrieveVLANRejected(t *testing.T) {
	s, err := parse.ParseSpec("TUN,retrieve-vlan")
	if err != nil {
		t.Fatal(err)
	}
	_, err = openTUN(context.Background(), s, xio.ModeRDWR, nil)
	if err == nil || !strings.Contains(err.Error(), "AF_PACKET") {
		t.Fatalf("err=%v want AF_PACKET INTERFACE error", err)
	}
}

func TestPACKETAuxdataSetsockopt(t *testing.T) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(uint16(unix.ETH_P_ALL))))
	if err != nil {
		t.Skipf("AF_PACKET: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_AUXDATA, 1); err != nil {
		t.Fatalf("PACKET_AUXDATA: %v", err)
	}
}
