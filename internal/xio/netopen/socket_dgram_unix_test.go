//go:build linux || darwin

package netopen

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func unixSocketHex(path string) string {
	return "x" + hex.EncodeToString(append([]byte(path), 0))
}

func socketDgramSpec(kind string, domain, typ, proto int, addr string, extra string) string {
	s := fmt.Sprintf("%s:%d:%d:%d:%s", kind, domain, typ, proto, addr)
	if extra != "" {
		s += "," + extra
	}
	return s
}

func openSocketKind(t *testing.T, raw string, mode xio.Mode) *xio.Opened {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	s := mustSocketSpec(t, raw)
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	o, err := xio.OpenSpec(ctx, s, mode, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o
}

func dgramPort(t *testing.T, st any) int {
	t.Helper()
	var addr net.Addr
	switch a := st.(type) {
	case interface{ LocalAddr() net.Addr }:
		addr = a.LocalAddr()
	case interface{ Addr() net.Addr }:
		addr = a.Addr()
	case net.Addr:
		addr = a
	default:
		t.Fatalf("no address on %T", st)
	}
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.Port
	case *net.TCPAddr:
		return a.Port
	default:
		t.Fatalf("local addr %T %v", a, a)
	}
	return 0
}

func readSocketDeadline(t *testing.T, r io.Reader, timeout time.Duration) ([]byte, error) {
	t.Helper()
	if d, ok := r.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(time.Now().Add(timeout))
	}
	buf := make([]byte, 64)
	n, err := r.Read(buf)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), buf[:n]...), nil
}

func listenSocketTestUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestSendtoPeerMatchesIPv6AddrAndPortOnly(t *testing.T) {
	ip := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	// port + flowinfo + addr (scope omitted, matching a tight packed sockaddr)
	data := make([]byte, 2+4+16)
	data[0], data[1] = 0, 9
	copy(data[6:], ip[:])
	sa, err := packRawSockaddr(unix.AF_INET6, data)
	if err != nil {
		t.Fatal(err)
	}
	peer := &unix.SockaddrInet6{Port: 9, Addr: ip, ZoneId: 7}
	if !sendtoPeerMatches(sa, peer) {
		t.Fatal("IPv6 SENDTO must match addr+port and ignore scope/flowinfo")
	}
	other := &unix.SockaddrInet6{Port: 9, Addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}}
	if sendtoPeerMatches(sa, other) {
		t.Fatal("wrong IPv6 peer must not match")
	}
}

func TestSocketUnixRangeRejected(t *testing.T) {
	path := unixSocketTestPath(t, "range.sock")
	_, err := xio.OpenSpec(context.Background(), mustSocketSpec(t, socketDgramSpec("SOCKET-DATAGRAM", unix.AF_UNIX, unix.SOCK_DGRAM, 0,
		unixSocketHex(path), "range=127.0.0.0/8")), xio.ModeRDWR, useGlobal())
	if err == nil {
		t.Fatal("expected range on AF_UNIX SOCKET-DATAGRAM to fail")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("range option not supported with address family")) {
		t.Fatalf("err=%v", err)
	}
}

func TestSocketSendtoUnixMissingPeerDoesNotHang(t *testing.T) {
	local := unixSocketTestPath(t, "local.sock")
	missing := unixSocketTestPath(t, "missing.sock")
	start := time.Now()
	_ = openSocketKind(t, socketDgramSpec("SOCKET-SENDTO", unix.AF_UNIX, unix.SOCK_DGRAM, 0,
		unixSocketHex(missing), "bind="+unixSocketHex(local)), xio.ModeRDWR)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("SOCKET-SENDTO hung %s waiting for a missing peer", elapsed)
	}
}

func TestSocketRecvWriteModeRejected(t *testing.T) {
	_, err := xio.OpenSpec(context.Background(), mustSocketSpec(t, socketDgramSpec("SOCKET-RECV", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP,
		ipv4SocketHex(0, [4]byte{127, 0, 0, 1}), "")), xio.ModeWrite, useGlobal())
	if err == nil {
		t.Fatal("expected SOCKET-RECV write-only open to fail")
	}
	if err.Error() != "SOCKET-RECV is read-only" {
		t.Fatalf("err=%q want SOCKET-RECV is read-only", err)
	}
}

func TestSocketRecvRangeFilter(t *testing.T) {
	o := openSocketKind(t, socketDgramSpec("SOCKET-RECV", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP,
		ipv4SocketHex(0, [4]byte{127, 0, 0, 1}), "range=127.0.0.0/8"), xio.ModeRead)
	port := dgramPort(t, o.Stream)
	src := listenSocketTestUDP(t)
	if _, err := src.WriteTo([]byte("ok-recv"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}); err != nil {
		t.Fatal(err)
	}
	got, err := readSocketDeadline(t, o.Stream, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ok-recv" {
		t.Fatalf("RECV got %q", got)
	}
}

func TestSocketRecvfromForkMaxChildrenZero(t *testing.T) {
	spec := mustSocketSpec(t, socketDgramSpec("SOCKET-RECVFROM", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP,
		ipv4SocketHex(0, [4]byte{127, 0, 0, 1}), "fork,max-children=0"))
	_, err := xio.OpenSpec(context.Background(), spec, xio.ModeRDWR, useGlobal())
	if err == nil {
		t.Fatal("expected max-children=0 to fail after bind")
	}
}
