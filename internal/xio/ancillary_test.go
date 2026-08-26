//go:build unix

package xio

import (
	"encoding/binary"
	"net"
	"testing"

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

func TestAncillaryBSDRecvTTLSetsIPTTL(t *testing.T) {
	// Darwin/FreeBSD recvmsg delivers TTL as IP_RECVTTL (byte or int), not
	// Linux IP_TTL. The session env name stays IP_TTL (classic xio-ip.c).
	g := &Global{}
	handleIPv4Cmsg(unix.IP_RECVTTL, []byte{64}, g)
	if got := g.SessionVars["IP_TTL"]; got != "64" {
		t.Fatalf("session env=%v want IP_TTL=64", g.SessionVars)
	}
}

func TestAncillaryRecvTOSSetsIPTOS(t *testing.T) {
	g := &Global{}
	handleIPv4Cmsg(unix.IP_RECVTOS, []byte{0x10}, g)
	if got := g.SessionVars["IP_TOS"]; got != "16" {
		t.Fatalf("session env=%v want IP_TOS=16", g.SessionVars)
	}
}

func TestNeedAncillaryBoolOption(t *testing.T) {
	on, err := parse.ParseSpec("UDP4:127.0.0.1:1,pktinfo")
	if err != nil {
		t.Fatal(err)
	}
	if !NeedAncillary(on) {
		t.Fatal("pktinfo presence must enable ReadMsg")
	}
	off, err := parse.ParseSpec("UDP4:127.0.0.1:1,pktinfo=0")
	if err != nil {
		t.Fatal(err)
	}
	if NeedAncillary(off) {
		t.Fatal("pktinfo=0 must not enable ReadMsg")
	}
	valued, err := parse.ParseSpec("UDP4:127.0.0.1:1,ip-recvttl=1")
	if err != nil {
		t.Fatal(err)
	}
	if !NeedAncillary(valued) {
		t.Fatal("ip-recvttl=1 must enable ReadMsg")
	}
}

func TestUDPRecvTTLAncillary(t *testing.T) {
	recv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recv.Close() })
	spec, err := parse.ParseSpec("UDP-RECV:0,ip-recvttl")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyUDPConnOpts(recv, spec, "udp4"); err != nil {
		t.Fatal(err)
	}
	raw, err := recv.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var enabled int
	var gerr error
	_ = raw.Control(func(fd uintptr) {
		enabled, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTTL)
	})
	if gerr != nil {
		t.Fatal(gerr)
	}
	if enabled == 0 {
		t.Fatal("IP_RECVTTL not enabled")
	}

	send, err := net.DialUDP("udp4", nil, recv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = send.Close() })
	if _, err := send.Write([]byte("ttl")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, oob, _, err := ReadUDPMsg(recv, buf, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ttl" {
		t.Fatalf("payload=%q", buf[:n])
	}
	if len(oob) == 0 {
		t.Fatal("expected IP_TTL cmsg")
	}
	g := &Global{}
	ProcessAncillary(oob, g)
	if g.SessionVars["IP_TTL"] == "" {
		msgs, _ := unix.ParseSocketControlMessage(oob)
		types := make([]int32, 0, len(msgs))
		for _, m := range msgs {
			types = append(types, m.Header.Type)
		}
		t.Fatalf("session env=%v want IP_TTL; cmsg types=%v IP_TTL=%d IP_RECVTTL=%d",
			g.SessionVars, types, unix.IP_TTL, unix.IP_RECVTTL)
	}
}

func TestTCPConnIPTTL(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accept := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accept <- nil
			return
		}
		accept <- c
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	srv := <-accept
	if srv == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = srv.Close() })
	spec, err := parse.ParseSpec("TCP4:127.0.0.1:1,ip-ttl=9,ip-tos=0x10")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyTCPConnOpts(spec, cli); err != nil {
		t.Fatal(err)
	}
	raw, err := cli.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ttl, tos int
	var gerr error
	_ = raw.Control(func(fd uintptr) {
		ttl, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
		if gerr != nil {
			return
		}
		tos, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS)
	})
	if gerr != nil {
		t.Fatal(gerr)
	}
	if ttl != 9 {
		t.Fatalf("IP_TTL=%d want 9", ttl)
	}
	if tos != 0x10 {
		t.Fatalf("IP_TOS=%#x want 0x10", tos)
	}
}
