//go:build unix

package xio

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
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

func TestAncillaryEnvironmentIsSessionScoped(t *testing.T) {
	var data [4]byte
	binary.NativeEndian.PutUint32(data[:], 42)
	g := &Global{}
	handleIPv4Cmsg(unix.IP_TTL, data[:], g)
	if got := g.SessionVars["IP_TTL"]; got != "42" {
		t.Fatalf("IP_TTL=%q", got)
	}
}

func TestNeedAncillaryFollowsPktinfoAndTimestamp(t *testing.T) {
	on, err := parse.ParseSpec("UDP4:127.0.0.1:1,pktinfo")
	if err != nil {
		t.Fatal(err)
	}
	if !NeedAncillary(on) {
		t.Fatal("pktinfo should request control messages")
	}
	ts, err := parse.ParseSpec("UDP4:127.0.0.1:1,so-timestamp")
	if err != nil {
		t.Fatal(err)
	}
	if !NeedAncillary(ts) {
		t.Fatal("so-timestamp should request control messages")
	}
	off, err := parse.ParseSpec("UDP4:127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if NeedAncillary(off) {
		t.Fatal("plain UDP should not request control messages")
	}
}

func TestReadUDPMsgWithPktinfo(t *testing.T) {
	s, err := parse.ParseSpec("UDP4-RECVFROM:0,pktinfo")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	if err := ApplyUDPConnOpts(pc, s, "udp4"); err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUDP("udp4", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	const payload = "cmsg-hi"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := pc.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, oob, addr, err := ReadUDPMsg(pc, buf, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != payload {
		t.Fatalf("payload %q", buf[:n])
	}
	if addr == nil {
		t.Fatal("missing peer addr")
	}
	g := &Global{}
	ProcessAncillary(oob, g)
	if len(oob) > 0 && g.SessionVars["IP_DSTADDR"] == "" && g.SessionVars["IP_LOCADDR"] == "" {
		t.Fatalf("pktinfo cmsg present but no dest vars: %v", g.SessionVars)
	}
}
