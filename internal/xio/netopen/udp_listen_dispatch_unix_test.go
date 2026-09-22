//go:build linux || darwin

package netopen

import (
	"bytes"
	"net"
	"strconv"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"golang.org/x/sys/unix"
)

func TestUDPAddrFromSockaddrKeepsNumericZone(t *testing.T) {
	const index = 1<<30 - 1
	var addr [16]byte
	addr[0] = 0xfe
	addr[1] = 0x80
	addr[15] = 1
	sa := &unix.SockaddrInet6{Port: 9, Addr: addr, ZoneId: index}

	var buf bytes.Buffer
	log := logx.New()
	log.SetOutput(&buf)
	got, err := udpAddrFromSockaddr(sa, log)
	if err != nil {
		t.Fatalf("missing interface index aborted the listener path: %v", err)
	}
	want := strconv.FormatUint(uint64(index), 10)
	if got.Zone != want {
		t.Fatalf("zone=%q want numeric %s", got.Zone, want)
	}
	if !bytes.Contains(buf.Bytes(), []byte(want)) {
		t.Fatalf("log %q does not mention zone %s", buf.String(), want)
	}
}

func TestUDPAddrFromSockaddrNamesRealInterface(t *testing.T) {
	ifi := firstInterface(t)
	var addr [16]byte
	addr[0] = 0xfe
	addr[1] = 0x80
	addr[15] = 1
	sa := &unix.SockaddrInet6{Port: 9, Addr: addr, ZoneId: uint32(ifi.Index)}
	got, err := udpAddrFromSockaddr(sa, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Zone != ifi.Name {
		t.Fatalf("zone=%q want %s", got.Zone, ifi.Name)
	}
	// The name lookup is cached: a second call still returns the name.
	again, err := udpAddrFromSockaddr(sa, nil)
	if err != nil {
		t.Fatal(err)
	}
	if again.Zone != ifi.Name {
		t.Fatalf("cached zone=%q want %s", again.Zone, ifi.Name)
	}
}

func TestUDPAddrFromSockaddrIgnoresUnscoped(t *testing.T) {
	ip := net.IPv4(127, 0, 0, 1).To4()
	var addr [4]byte
	copy(addr[:], ip)
	sa := &unix.SockaddrInet4{Port: 9, Addr: addr}
	got, err := udpAddrFromSockaddr(sa, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Zone != "" || !got.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("addr=%v", got)
	}
}
