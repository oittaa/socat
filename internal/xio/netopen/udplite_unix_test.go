//go:build linux

package netopen

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func skipIfNoUDPLITE(t *testing.T) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDPLITE)
	if err != nil {
		t.Skipf("no kernel UDP-Lite: %v", err)
	}
	_ = unix.Close(fd)
}

func skipIfNoUDPLITE6(t *testing.T) {
	t.Helper()
	skipIfNoUDPLITE(t)
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDPLITE)
	if err != nil {
		t.Skipf("no kernel IPv6 UDP-Lite: %v", err)
	}
	_ = unix.Close(fd)
	pc, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	_ = pc.Close()
}

func listenUDPLITE4Probe(t *testing.T) net.PacketConn {
	t.Helper()
	skipIfNoUDPLITE(t)
	pc, err := listenIPDgram(context.Background(), "udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, parse.Spec{Type: "UDPLITE4-SENDTO"}, ipprotoUDPLITE)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

func TestUDPLITE4SendtoIgnoresWrongPeer(t *testing.T) {
	skipIfNoUDPLITE(t)
	testSendtoIgnoresWrongPeer(t, "UDPLITE4-SENDTO", listenUDPLITE4Probe)
}

func TestUDPLITE4DatagramAcceptsWrongPeerByDefault(t *testing.T) {
	skipIfNoUDPLITE(t)
	testDatagramAcceptsWrongPeer(t, "UDPLITE4-DATAGRAM", listenUDPLITE4Probe)
}

func TestUDPLITE4DatagramRangeFilter(t *testing.T) {
	skipIfNoUDPLITE(t)
	testDatagramRangeFilter(t, "UDPLITE4-DATAGRAM", listenUDPLITE4Probe)
}

func TestUDPLITE4DatagramSourceportFilter(t *testing.T) {
	skipIfNoUDPLITE(t)
	testDatagramSourceportFilter(t, "UDPLITE4-DATAGRAM", listenUDPLITE4Probe)
}

func TestUDPLITE4DatagramTCPWrapFilter(t *testing.T) {
	skipIfNoUDPLITE(t)
	testDatagramTCPWrapFilter(t, "UDPLITE4-DATAGRAM", listenUDPLITE4Probe)
}

func TestUDPLITE6ListenConnectEcho(t *testing.T) {
	skipIfNoUDPLITE6(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv := startNetListenPIPE(t, ctx, useGlobal(), "UDPLITE6-LISTEN:0,reuseaddr,fork,bind=[::1]")
	t.Cleanup(func() { _ = srv.Close() })
	ua, ok := srv.Listener.Addr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("listen addr %T", srv.Listener.Addr())
	}
	cli, err := xio.OpenChannel(ctx, parseChannel(t, "UDPLITE6:[::1]:"+strconv.Itoa(ua.Port)+",connect-timeout=2"), xio.ModeRDWR, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	echoConn(t, cli.Stream, []byte("udplite6-hi"))
}

func TestUDPSockaddrIPv6Zone(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("no lo interface: %v", err)
	}
	id, ok := xio.Uint32FromInt(lo.Index)
	if !ok {
		t.Fatalf("lo index %d out of range", lo.Index)
	}
	sa, err := udpSockaddr(unix.AF_INET6, &net.UDPAddr{IP: net.ParseIP("::1"), Port: 9, Zone: "lo"})
	if err != nil {
		t.Fatal(err)
	}
	inet6, ok := sa.(*unix.SockaddrInet6)
	if !ok {
		t.Fatalf("type %T", sa)
	}
	if inet6.ZoneId != id {
		t.Fatalf("name zone=%d want %d", inet6.ZoneId, id)
	}
	sa, err = udpSockaddr(unix.AF_INET6, &net.UDPAddr{IP: net.ParseIP("::1"), Port: 9, Zone: strconv.Itoa(lo.Index)})
	if err != nil {
		t.Fatal(err)
	}
	inet6 = sa.(*unix.SockaddrInet6)
	if inet6.ZoneId != id {
		t.Fatalf("numeric zone=%d want %d", inet6.ZoneId, id)
	}
	if _, err := udpSockaddr(unix.AF_INET6, &net.UDPAddr{IP: net.ParseIP("::1"), Port: 9, Zone: "no-such-udplite-iface"}); err == nil {
		t.Fatal("unknown interface name must error")
	}
	if _, err := udpSockaddr(unix.AF_INET6, &net.UDPAddr{IP: net.ParseIP("::1"), Port: 9, Zone: "4294967296"}); err == nil {
		t.Fatal("overflowing numeric zone must error")
	}
}

func TestUDPLITE6UnknownZoneErrors(t *testing.T) {
	skipIfNoUDPLITE6(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := xio.OpenChannel(ctx, parseChannel(t, "UDPLITE6-LISTEN:0,bind=[::1%no-such-udplite-iface]"), xio.ModeRDWR, useGlobal())
	if err == nil {
		t.Fatal("expected IPv6 zone error")
	}
	if !strings.Contains(err.Error(), "no-such-udplite-iface") {
		t.Fatalf("error %v does not mention zone", err)
	}
}

func packetSOProtocol(t *testing.T, sc syscall.Conn) int {
	t.Helper()
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var proto int
	var sockErr error
	controlErr := raw.Control(func(fd uintptr) {
		proto, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL)
	})
	if err := errors.Join(controlErr, sockErr); err != nil {
		t.Fatal(err)
	}
	return proto
}

func TestListenUDPNativeStaysIPPROTOUDP(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4-LISTEN:0,bind=127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := listenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	if got := packetSOProtocol(t, pc); got != unix.IPPROTO_UDP {
		t.Fatalf("UDP SO_PROTOCOL=%d want %d", got, unix.IPPROTO_UDP)
	}
}

func TestUDPLITESocketsKeepIPPROTOUDPLITE(t *testing.T) {
	skipIfNoUDPLITE(t)
	ctx := t.Context()
	listenSpec, err := parse.ParseSpec("UDPLITE4-LISTEN:0,bind=127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := listenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, listenSpec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if got := packetSOProtocol(t, ln); got != unix.IPPROTO_UDPLITE {
		t.Fatalf("LISTEN SO_PROTOCOL=%d want %d", got, unix.IPPROTO_UDPLITE)
	}
	port := ln.LocalAddr().(*net.UDPAddr).Port
	remote := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	connectSpec, err := parse.ParseSpec("UDPLITE4:127.0.0.1:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialUDPForSpec(ctx, "udp4", nil, remote, connectSpec, nil, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	uc, ok := conn.(*net.UDPConn)
	if !ok {
		t.Fatalf("connect type %T", conn)
	}
	if got := packetSOProtocol(t, uc); got != unix.IPPROTO_UDPLITE {
		t.Fatalf("CONNECT SO_PROTOCOL=%d want %d", got, unix.IPPROTO_UDPLITE)
	}

	for _, typ := range []string{
		"UDPLITE4-SENDTO:127.0.0.1:" + strconv.Itoa(port),
		"UDPLITE4-DATAGRAM:127.0.0.1:" + strconv.Itoa(port),
		"UDPLITE4-RECV:0,bind=127.0.0.1",
		"UDPLITE4-RECVFROM:0,bind=127.0.0.1",
	} {
		spec, err := parse.ParseSpec(typ)
		if err != nil {
			t.Fatal(err)
		}
		pc, err := listenPacketForSpec(ctx, "udp4", "127.0.0.1:0", spec)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		got := packetSOProtocol(t, pc.(*net.UDPConn))
		_ = pc.Close()
		if got != unix.IPPROTO_UDPLITE {
			t.Errorf("%s SO_PROTOCOL=%d want %d", spec.Type, got, unix.IPPROTO_UDPLITE)
		}
	}
}

func TestUDPLITEListenConnectEcho(t *testing.T) {
	skipIfNoUDPLITE(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv := startNetListenPIPE(t, ctx, useGlobal(), "UDPLITE4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1")
	t.Cleanup(func() { _ = srv.Close() })
	ua, ok := srv.Listener.Addr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("listen addr %T", srv.Listener.Addr())
	}
	cli, err := xio.OpenChannel(ctx, parseChannel(t, "UDPLITE4:127.0.0.1:"+strconv.Itoa(ua.Port)+",connect-timeout=2"), xio.ModeRDWR, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	echoConn(t, cli.Stream, []byte("udplite-hi"))
}

func TestUDPLITE4LAliasListenEcho(t *testing.T) {
	skipIfNoUDPLITE(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv := startNetListenPIPE(t, ctx, useGlobal(), "UDPLITE4-L:0,reuseaddr,fork,bind=127.0.0.1")
	t.Cleanup(func() { _ = srv.Close() })
	ua, ok := srv.Listener.Addr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("listen addr %T", srv.Listener.Addr())
	}
	cli, err := xio.OpenChannel(ctx, parseChannel(t, "UDPLITE4:127.0.0.1:"+strconv.Itoa(ua.Port)), xio.ModeRDWR, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	echoConn(t, cli.Stream, []byte("udplite-alias"))
}

func TestUDPLITE4SendtoRecv(t *testing.T) {
	skipIfNoUDPLITE(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	recv, err := xio.OpenChannel(ctx, parseChannel(t, "UDPLITE4-RECV:0,bind=127.0.0.1"), xio.ModeRead, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recv.Close() })
	la, ok := recv.Stream.(interface{ LocalAddr() net.Addr })
	if !ok {
		t.Fatal("UDPLITE-RECV stream has no LocalAddr")
	}
	port := la.LocalAddr().(*net.UDPAddr).Port
	send, err := xio.OpenChannel(ctx, parseChannel(t, "UDPLITE4-SENDTO:127.0.0.1:"+strconv.Itoa(port)), xio.ModeWrite, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = send.Close() })
	const payload = "udplite-sendto"
	if _, err := send.Stream.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if d, ok := recv.Stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(time.Now().Add(3 * time.Second))
	}
	if _, err := io.ReadFull(recv.Stream, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("UDPLITE-RECV got %q", got)
	}
}

func TestUDPLITE4DatagramToRecv(t *testing.T) {
	skipIfNoUDPLITE(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	recv, err := xio.OpenChannel(ctx, parseChannel(t, "UDPLITE4-RECV:0,bind=127.0.0.1"), xio.ModeRead, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recv.Close() })
	la, ok := recv.Stream.(interface{ LocalAddr() net.Addr })
	if !ok {
		t.Fatal("UDPLITE-RECV stream has no LocalAddr")
	}
	port := la.LocalAddr().(*net.UDPAddr).Port
	dgram, err := xio.OpenChannel(ctx, parseChannel(t, "UDPLITE4-DATAGRAM:127.0.0.1:"+strconv.Itoa(port)), xio.ModeWrite, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dgram.Close() })
	const payload = "udplite-dgram"
	if _, err := dgram.Stream.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if d, ok := recv.Stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(time.Now().Add(3 * time.Second))
	}
	if _, err := io.ReadFull(recv.Stream, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("UDPLITE-RECV got %q", got)
	}
}

func TestUDPLITE4RecvfromReply(t *testing.T) {
	skipIfNoUDPLITE(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pc, err := listenIPDgram(ctx, "udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, parse.Spec{Type: "UDPLITE4-RECVFROM"}, ipprotoUDPLITE)
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	spec := parseChannel(t, "UDPLITE4-RECVFROM:"+strconv.Itoa(port)+",bind=127.0.0.1,reuseaddr=0")
	opened := make(chan *xio.Opened, 1)
	errCh := make(chan error, 1)
	go func() {
		o, err := xio.OpenChannel(ctx, spec, xio.ModeRDWR, useGlobal())
		if err != nil {
			errCh <- err
			return
		}
		opened <- o
	}()
	cli, err := dialIPDgram(ctx, "udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, parse.Spec{Type: "UDPLITE4"}, ipprotoUDPLITE, nil, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	const payload = "udplite-recvfrom"
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(4 * time.Second)
	var o *xio.Opened
	for o == nil {
		select {
		case o = <-opened:
		case e := <-errCh:
			t.Fatal(e)
		case <-ticker.C:
			_, _ = cli.Write([]byte(payload))
		case <-timeout:
			t.Fatal("UDPLITE-RECVFROM open timed out")
		}
	}
	t.Cleanup(func() { _ = o.Close() })
	got := make([]byte, len(payload))
	if d, ok := o.Stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(time.Now().Add(3 * time.Second))
	}
	if _, err := io.ReadFull(o.Stream, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("UDPLITE-RECVFROM got %q", got)
	}
	if _, err := o.Stream.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, err := cli.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != payload {
		t.Fatalf("UDPLITE-RECVFROM reply %q", buf[:n])
	}
}

func TestUDPLITECscovSetsockopt(t *testing.T) {
	skipIfNoUDPLITE(t)
	spec, err := parse.ParseSpec("UDPLITE4-LISTEN:0,bind=127.0.0.1,udplite-send-cscov=8,udplite-recv-cscov=8")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := listenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	raw, err := pc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var sendCov, recvCov int
	var sockErr error
	controlErr := raw.Control(func(fd uintptr) {
		sendCov, sockErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_UDPLITE, udpliteSendCscov)
		if sockErr == nil {
			recvCov, sockErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_UDPLITE, udpliteRecvCscov)
		}
	})
	if err := errors.Join(controlErr, sockErr); err != nil {
		t.Fatal(err)
	}
	if sendCov != 8 {
		t.Fatalf("udplite-send-cscov=%d want 8", sendCov)
	}
	if recvCov != 8 {
		t.Fatalf("udplite-recv-cscov=%d want 8", recvCov)
	}
}
