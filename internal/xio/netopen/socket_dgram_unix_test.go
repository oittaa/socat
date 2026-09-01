//go:build linux || darwin

package netopen

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func ipv4SocketHexTight(port int, ip [4]byte) string {
	buf := []byte{byte(port >> 8), byte(port), ip[0], ip[1], ip[2], ip[3]}
	return "x" + hex.EncodeToString(buf)
}

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
	var o *xio.Opened
	var err error
	switch s.Type {
	case "SOCKET-SENDTO":
		o, err = openSocketSendto(ctx, s, mode, g)
	case "SOCKET-DATAGRAM":
		o, err = openSocketDatagram(ctx, s, mode, g)
	case "SOCKET-RECV":
		o, err = openSocketRecv(ctx, s, mode, g)
	default:
		t.Fatalf("openSocketKind: %s", s.Type)
	}
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

func TestSendtoPeerMatchesIPv4Padding(t *testing.T) {
	ip := [4]byte{127, 0, 0, 1}
	peer := &unix.SockaddrInet4{Port: 9, Addr: ip}
	for _, name := range []string{"tight", "padded"} {
		t.Run(name, func(t *testing.T) {
			raw := ipv4SocketHexTight(9, ip)
			if name == "padded" {
				raw = ipv4SocketHex(9, ip)
			}
			data, err := xio.ParseSocatData(raw)
			if err != nil {
				t.Fatal(err)
			}
			sa, err := packRawSockaddr(unix.AF_INET, data)
			if err != nil {
				t.Fatal(err)
			}
			if !sendtoPeerMatches(sa, peer) {
				t.Fatal("configured IPv4 sockaddr must match kernel recvfrom peer")
			}
			other := &unix.SockaddrInet4{Port: 9, Addr: [4]byte{127, 1, 0, 1}}
			if sendtoPeerMatches(sa, other) {
				t.Fatal("wrong IPv4 peer must not match")
			}
		})
	}
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

func TestSocketDatagramStaysUnconnectedAndAcceptsOtherSender(t *testing.T) {
	o := openSocketKind(t, socketDgramSpec("SOCKET-DATAGRAM", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP,
		ipv4SocketHex(9, [4]byte{192, 0, 2, 1}),
		"bind="+ipv4SocketHex(0, [4]byte{127, 0, 0, 1})), xio.ModeRDWR)
	assertUnconnected(t, o.Stream)
	port := dgramPort(t, o.Stream)

	src := listenSocketTestUDP(t)
	if _, err := src.WriteTo([]byte("from-other"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}); err != nil {
		t.Fatal(err)
	}
	got, err := readSocketDeadline(t, o.Stream, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "from-other" {
		t.Fatalf("DATAGRAM read %q want from-other (must stay unconnected)", got)
	}

	dest := listenSocketTestUDP(t)
	dport := dest.LocalAddr().(*net.UDPAddr).Port
	writer := openSocketKind(t, socketDgramSpec("SOCKET-DATAGRAM", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP,
		ipv4SocketHex(dport, [4]byte{127, 0, 0, 1}),
		"bind="+ipv4SocketHex(0, [4]byte{127, 0, 0, 1})), xio.ModeRDWR)
	if _, err := writer.Stream.Write([]byte("to-peer")); err != nil {
		t.Fatal(err)
	}
	_ = dest.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _, err := dest.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "to-peer" {
		t.Fatalf("DATAGRAM write %q want to-peer", buf[:n])
	}
}

func TestSocketSendtoIgnoresWrongPeerAndAcceptsPaddedReply(t *testing.T) {
	dest := listenSocketTestUDP(t)
	dport := dest.LocalAddr().(*net.UDPAddr).Port

	o := openSocketKind(t, socketDgramSpec("SOCKET-SENDTO", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP,
		ipv4SocketHexTight(dport, [4]byte{127, 0, 0, 1}),
		"bind="+ipv4SocketHex(0, [4]byte{127, 0, 0, 1})), xio.ModeRDWR)
	assertUnconnected(t, o.Stream)
	sport := dgramPort(t, o.Stream)

	wrong := listenSocketTestUDP(t)
	if _, err := wrong.WriteTo([]byte("nope"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sport}); err != nil {
		t.Fatal(err)
	}
	if _, err := dest.WriteTo([]byte("from-peer"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sport}); err != nil {
		t.Fatal(err)
	}
	got, err := readSocketDeadline(t, o.Stream, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "from-peer" {
		t.Fatalf("SENDTO read %q want from-peer", got)
	}
}

func TestSocketDatagramRangeFilter(t *testing.T) {
	denied := openSocketKind(t, socketDgramSpec("SOCKET-DATAGRAM", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP,
		ipv4SocketHex(9, [4]byte{127, 0, 0, 1}),
		"bind="+ipv4SocketHex(0, [4]byte{127, 0, 0, 1})+",range=10.0.0.0/8"), xio.ModeRDWR)
	port := dgramPort(t, denied.Stream)
	src := listenSocketTestUDP(t)
	if _, err := src.WriteTo([]byte("nope"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}); err != nil {
		t.Fatal(err)
	}
	if _, err := readSocketDeadline(t, denied.Stream, 200*time.Millisecond); err == nil {
		t.Fatal("range=10.0.0.0/8 accepted a loopback sender")
	}

	allowed := openSocketKind(t, socketDgramSpec("SOCKET-DATAGRAM", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP,
		ipv4SocketHex(9, [4]byte{127, 0, 0, 1}),
		"bind="+ipv4SocketHex(0, [4]byte{127, 0, 0, 1})+",range=127.0.0.0/8"), xio.ModeRDWR)
	aport := dgramPort(t, allowed.Stream)
	if _, err := src.WriteTo([]byte("ok-range"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: aport}); err != nil {
		t.Fatal(err)
	}
	got, err := readSocketDeadline(t, allowed.Stream, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ok-range" {
		t.Fatalf("range=127.0.0.0/8 got %q", got)
	}
}

func TestSocketUnixRangeRejected(t *testing.T) {
	path := unixSocketTestPath(t, "range.sock")
	_, err := openSocketDatagram(context.Background(), mustSocketSpec(t, socketDgramSpec("SOCKET-DATAGRAM", unix.AF_UNIX, unix.SOCK_DGRAM, 0,
		unixSocketHex(path), "range=127.0.0.0/8")), xio.ModeRDWR, useGlobal())
	if err == nil {
		t.Fatal("expected range on AF_UNIX SOCKET-DATAGRAM to fail")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("range option not supported with address family")) {
		t.Fatalf("err=%v", err)
	}
}

func TestSocketSendtoUnixNamedWrongPeer(t *testing.T) {
	dest := unixSocketTestPath(t, "dest.sock")
	local := unixSocketTestPath(t, "local.sock")
	wrong := unixSocketTestPath(t, "wrong.sock")
	peer, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: dest, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	other, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: wrong, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })

	o := openSocketKind(t, socketDgramSpec("SOCKET-SENDTO", unix.AF_UNIX, unix.SOCK_DGRAM, 0,
		unixSocketHex(dest), "bind="+unixSocketHex(local)), xio.ModeRDWR)
	target := &net.UnixAddr{Name: local, Net: "unixgram"}
	if _, err := other.WriteToUnix([]byte("nope"), target); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUnix([]byte("from-dest"), target); err != nil {
		t.Fatal(err)
	}
	got, err := readSocketDeadline(t, o.Stream, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "from-dest" {
		t.Fatalf("read %q want from-dest (named wrong peer must be dropped)", got)
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
	_, err := openSocketRecv(context.Background(), mustSocketSpec(t, socketDgramSpec("SOCKET-RECV", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP,
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

func TestSocketRecvfromNonForkOneShotAndPeerAddr(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec := mustSocketSpec(t, socketDgramSpec("SOCKET-RECVFROM", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP,
		ipv4SocketHex(0, [4]byte{127, 0, 0, 1}), "reuseaddr"))
	bound := make(chan net.Addr, 1)
	var boundOnce sync.Once
	defer xio.SetListenBoundTestHook(func(addr net.Addr) {
		boundOnce.Do(func() { bound <- addr })
	})()
	opened := make(chan *xio.Opened, 1)
	errc := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	go func() {
		o, err := openSocketRecvfrom(ctx, spec, xio.ModeRDWR, g)
		if err != nil {
			errc <- err
			return
		}
		opened <- o
	}()
	var addr net.Addr
	select {
	case addr = <-bound:
	case err := <-errc:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("SOCKET-RECVFROM did not bind")
	}
	port := dgramPort(t, addr)
	src := listenSocketTestUDP(t)
	srcPort := src.LocalAddr().(*net.UDPAddr).Port
	payload := []byte("oneshot")
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var o *xio.Opened
	for o == nil {
		select {
		case <-ticker.C:
			_, _ = src.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		case err := <-errc:
			t.Fatal(err)
		case o = <-opened:
		case <-ctx.Done():
			t.Fatal("timed out opening SOCKET-RECVFROM")
		}
	}
	t.Cleanup(func() { _ = o.Close() })
	if g.PeerAddr != "127.0.0.1" || g.PeerPort != strconv.Itoa(srcPort) {
		t.Fatalf("peer=%s:%s want 127.0.0.1:%d", g.PeerAddr, g.PeerPort, srcPort)
	}
	got, err := readSocketDeadline(t, o.Stream, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("first read %q want %q", got, payload)
	}
	n, err := o.Stream.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("second read n=%d err=%v want EOF", n, err)
	}
}

func TestSocketRecvfromRangeFilter(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec := mustSocketSpec(t, socketDgramSpec("SOCKET-RECVFROM", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP,
		ipv4SocketHex(0, [4]byte{127, 0, 0, 1}), "reuseaddr,range=127.0.0.1/32"))
	bound := make(chan net.Addr, 1)
	var boundOnce sync.Once
	defer xio.SetListenBoundTestHook(func(addr net.Addr) {
		boundOnce.Do(func() { bound <- addr })
	})()
	opened := make(chan *xio.Opened, 1)
	errc := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	go func() {
		o, err := openSocketRecvfrom(ctx, spec, xio.ModeRDWR, g)
		if err != nil {
			errc <- err
			return
		}
		opened <- o
	}()
	var addr net.Addr
	select {
	case addr = <-bound:
	case err := <-errc:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("SOCKET-RECVFROM did not bind")
	}
	port := dgramPort(t, addr)
	allowed := listenSocketTestUDP(t)
	allowedPort := allowed.LocalAddr().(*net.UDPAddr).Port
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var o *xio.Opened
	for o == nil {
		select {
		case <-ticker.C:
			_, _ = allowed.WriteTo([]byte("ok-from"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		case err := <-errc:
			t.Fatal(err)
		case o = <-opened:
		case <-ctx.Done():
			t.Fatal("timed out opening ranged SOCKET-RECVFROM")
		}
	}
	t.Cleanup(func() { _ = o.Close() })
	if g.PeerAddr != "127.0.0.1" || g.PeerPort != strconv.Itoa(allowedPort) {
		t.Fatalf("peer=%s:%s want 127.0.0.1:%d", g.PeerAddr, g.PeerPort, allowedPort)
	}
	got, err := readSocketDeadline(t, o.Stream, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ok-from" {
		t.Fatalf("RECVFROM range read %q want ok-from", got)
	}
}

func TestSocketRecvfromCanceledAfterRejectedPeer(t *testing.T) {
	spec := mustSocketSpec(t, socketDgramSpec("SOCKET-RECVFROM", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP,
		ipv4SocketHex(0, [4]byte{127, 0, 0, 1}), "reuseaddr,range=192.0.2.0/24"))
	ctx, cancel := context.WithCancel(context.Background())
	bound := make(chan net.Addr, 1)
	var boundOnce sync.Once
	defer xio.SetListenBoundTestHook(func(addr net.Addr) {
		boundOnce.Do(func() { bound <- addr })
	})()
	done := make(chan error, 1)
	go func() {
		_, err := openSocketRecvfrom(ctx, spec, xio.ModeRDWR, &xio.Global{Log: logx.New()})
		done <- err
	}()
	select {
	case addr := <-bound:
		src := listenSocketTestUDP(t)
		if _, err := src.WriteTo([]byte("denied"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: dgramPort(t, addr)}); err != nil {
			t.Fatal(err)
		}
	case err := <-done:
		t.Fatalf("recvfrom ended before bind: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("SOCKET-RECVFROM did not bind")
	}
	select {
	case err := <-done:
		t.Fatalf("recvfrom accepted a peer outside range: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled SOCKET-RECVFROM did not return")
	}
}

func TestSocketRecvfromForkSessionsAndMaxChildren(t *testing.T) {
	spec := mustSocketSpec(t, socketDgramSpec("SOCKET-RECVFROM", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP,
		ipv4SocketHex(0, [4]byte{127, 0, 0, 1}), "reuseaddr,fork,max-children=2,readbytes=4"))
	o, err := openSocketRecvfrom(context.Background(), spec, xio.ModeRDWR, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.Kind != xio.KindListen || o.Listener == nil {
		t.Fatalf("Kind=%v listener=%v want KindListen", o.Kind, o.Listener)
	}
	if o.MaxChildren != 2 {
		t.Fatalf("MaxChildren=%d want 2", o.MaxChildren)
	}
	if o.PeerFilter != nil {
		t.Fatal("SOCKET-RECVFROM,fork must filter in Accept only")
	}
	assertWrapDialReadbytes(t, o)
	port := dgramPort(t, o.Listener)

	firstCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := o.Listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		firstCh <- c
	}()
	src := listenSocketTestUDP(t)
	srcPort := src.LocalAddr().(*net.UDPAddr).Port
	payload := []byte("fork1")
	deadline := time.Now().Add(4 * time.Second)
	var first net.Conn
	for first == nil && time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatal(err)
		case first = <-firstCh:
		default:
			_, _ = src.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
			time.Sleep(20 * time.Millisecond)
		}
	}
	if first == nil {
		t.Fatal("timed out accepting first RECVFROM fork session")
	}
	t.Cleanup(func() { _ = first.Close() })
	if ra, ok := first.RemoteAddr().(*net.UDPAddr); !ok || !ra.IP.Equal(net.IPv4(127, 0, 0, 1)) || ra.Port != srcPort {
		t.Fatalf("RemoteAddr=%v want 127.0.0.1:%d", first.RemoteAddr(), srcPort)
	}
	buf := make([]byte, 16)
	n, err := first.Read(buf)
	if err != nil || string(buf[:n]) != "fork1" {
		t.Fatalf("first session n=%d err=%v data=%q", n, err, buf[:n])
	}
}

func TestSocketRecvfromForkAppliesParentDescriptorOptions(t *testing.T) {
	var ops []string
	restore := xio.InstallLifecycleSyscallHook(func(op string) { ops = append(ops, op) })
	t.Cleanup(restore)
	spec := mustSocketSpec(t, socketDgramSpec("SOCKET-RECVFROM", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP,
		ipv4SocketHex(0, [4]byte{127, 0, 0, 1}), "fork,append,sndbuf-late=65536"))
	o, err := openSocketRecvfrom(context.Background(), spec, xio.ModeRDWR, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	ln, ok := o.Listener.(*socketRecvfromListener)
	if !ok {
		t.Fatalf("Listener=%T want *socketRecvfromListener", o.Listener)
	}
	if got := packetSockoptInt(t, ln.f, unix.SO_SNDBUF); got < 65536 {
		t.Fatalf("SO_SNDBUF=%d want >= 65536", got)
	}
	if packetFcntlFlags(t, ln.f)&unix.O_APPEND == 0 {
		t.Fatal("append did not reach the shared listener fd")
	}
	if n := countLifecycleOp(ops, "F_SETFL"); n != 1 {
		t.Fatalf("F_SETFL count=%d want 1 (ops=%v)", n, ops)
	}
}

func TestSocketRecvfromForkMaxChildrenZero(t *testing.T) {
	spec := mustSocketSpec(t, socketDgramSpec("SOCKET-RECVFROM", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP,
		ipv4SocketHex(0, [4]byte{127, 0, 0, 1}), "fork,max-children=0"))
	_, err := openSocketRecvfrom(context.Background(), spec, xio.ModeRDWR, useGlobal())
	if err == nil {
		t.Fatal("expected max-children=0 to fail after bind")
	}
}

func TestSocketRecvfromUnixOneShot(t *testing.T) {
	path := unixSocketTestPath(t, "recvfrom.sock")
	peerPath := unixSocketTestPath(t, "peer.sock")
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec := mustSocketSpec(t, socketDgramSpec("SOCKET-RECVFROM", unix.AF_UNIX, unix.SOCK_DGRAM, 0, unixSocketHex(path), ""))
	bound := make(chan struct{})
	var boundOnce sync.Once
	defer xio.SetListenBoundTestHook(func(net.Addr) {
		boundOnce.Do(func() { close(bound) })
	})()
	opened := make(chan *xio.Opened, 1)
	errc := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	go func() {
		o, err := openSocketRecvfrom(ctx, spec, xio.ModeRDWR, g)
		if err != nil {
			errc <- err
			return
		}
		opened <- o
	}()
	select {
	case <-bound:
	case err := <-errc:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("unix SOCKET-RECVFROM did not bind")
	}
	peer, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: peerPath, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	if _, err := peer.WriteToUnix([]byte("uone"), &net.UnixAddr{Name: path, Net: "unixgram"}); err != nil {
		t.Fatal(err)
	}
	select {
	case o := <-opened:
		t.Cleanup(func() { _ = o.Close() })
		got, err := readSocketDeadline(t, o.Stream, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "uone" {
			t.Fatalf("got %q", got)
		}
		n, err := o.Stream.Read(make([]byte, 8))
		if n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("second read n=%d err=%v want EOF", n, err)
		}
	case err := <-errc:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal("unix SOCKET-RECVFROM timed out")
	}
}

func assertUnconnected(t *testing.T, st any) {
	t.Helper()
	sc, ok := st.(syscall.Conn)
	if !ok {
		t.Fatalf("%T does not implement syscall.Conn", st)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		_, peerErr = unix.Getpeername(int(fd))
	}); err != nil {
		t.Fatal(err)
	}
	if peerErr == nil {
		t.Fatal("SOCKET-DATAGRAM must not connect")
	}
}
