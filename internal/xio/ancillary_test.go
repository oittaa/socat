package xio

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestParseCmsgTimeval16(t *testing.T) {
	var data [16]byte
	binary.NativeEndian.PutUint64(data[0:8], 1_700_000_000)
	binary.NativeEndian.PutUint64(data[8:16], 123456)
	sec, usec, ok := parseCmsgTimeval(data[:])
	if !ok || sec != 1_700_000_000 || usec != 123456 {
		t.Fatalf("got sec=%d usec=%d ok=%v", sec, usec, ok)
	}
}

func TestParseCmsgTimeval8(t *testing.T) {
	var data [8]byte
	binary.NativeEndian.PutUint32(data[0:4], 100)
	binary.NativeEndian.PutUint32(data[4:8], 50)
	sec, usec, ok := parseCmsgTimeval(data[:])
	if !ok || sec != 100 || usec != 50 {
		t.Fatalf("got sec=%d usec=%d ok=%v", sec, usec, ok)
	}
}

func TestParseCmsgTimevalShort(t *testing.T) {
	if _, _, ok := parseCmsgTimeval([]byte{1, 2, 3}); ok {
		t.Fatal("expected !ok")
	}
}

func TestParseInet4Pktinfo(t *testing.T) {
	var data [12]byte
	binary.NativeEndian.PutUint32(data[0:4], 2)
	copy(data[4:8], net.IPv4(10, 0, 0, 1).To4())
	copy(data[8:12], net.IPv4(10, 0, 0, 255).To4())
	ifi, spec, addr, ok := parseInet4Pktinfo(data[:])
	if !ok || ifi != 2 || spec.String() != "10.0.0.1" || addr.String() != "10.0.0.255" {
		t.Fatalf("ifi=%d spec=%s addr=%s ok=%v", ifi, spec, addr, ok)
	}
}

func TestParseInet6Pktinfo(t *testing.T) {
	var data [20]byte
	ip := net.ParseIP("2001:db8::1").To16()
	copy(data[0:16], ip)
	binary.NativeEndian.PutUint32(data[16:20], 7)
	ifi, addr, ok := parseInet6Pktinfo(data[:])
	if !ok || ifi != 7 || !addr.Equal(ip) {
		t.Fatalf("ifi=%d addr=%s ok=%v", ifi, addr, ok)
	}
}
