package netopen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

type udpAcceptResult struct {
	conn net.Conn
	err  error
}

func startUDPAccept(ln net.Listener) <-chan udpAcceptResult {
	ch := make(chan udpAcceptResult, 1)
	go func() {
		conn, err := ln.Accept()
		ch <- udpAcceptResult{conn: conn, err: err}
	}()
	return ch
}

func waitUDPAccept(t *testing.T, ch <-chan udpAcceptResult, timeout time.Duration, what string) net.Conn {
	t.Helper()
	select {
	case result := <-ch:
		if result.err != nil {
			t.Fatalf("%s: %v", what, result.err)
		}
		return result.conn
	case <-time.After(timeout):
		t.Fatalf("%s: Accept timed out (datagram likely routed to a connected child)", what)
		return nil
	}
}

func TestUDPForkInvalidRcvtimeoFailsOpen(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork,rcvtimeo=nope")
	if err != nil {
		t.Fatal(err)
	}
	_, err = openUDP4Listen(context.Background(), spec, xio.ModeRDWR, g)
	if err == nil {
		t.Fatal("expected rcvtimeo error")
	}
}

func TestUDPRecvFromConnShortReadDropsRemainder(t *testing.T) {
	u := &udpRecvFromConn{first: newFirstPacket([]byte("abcd")), closeEOF: true}
	buf := make([]byte, 1)
	n, err := u.Read(buf)
	if err != nil || n != 1 || buf[0] != 'a' {
		t.Fatalf("short read n=%d err=%v data=%q", n, err, buf[:n])
	}
	n, err = u.Read(buf)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("remainder n=%d err=%v want EOF", n, err)
	}
}

func TestUDPSessionConnHandoffNetConn(t *testing.T) {
	parent, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Close() })
	handed := &udpSessionConn{sock: parent, role: udpRoleHandoff}
	if got := handed.NetConn(); got != parent {
		t.Fatalf("handoff NetConn=%v want listener", got)
	}
}

func TestUDPRecvFromConnZeroLengthFirst(t *testing.T) {
	u := &udpRecvFromConn{first: newFirstPacket(nil), closeEOF: true}
	n, err := u.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("zero-length first n=%d err=%v want EOF", n, err)
	}
}

func parseUDPSpec(t *testing.T, raw string) parse.Spec {
	t.Helper()
	s, err := parse.ParseSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func listenUDPOnPort(t *testing.T, spec parse.Spec, port int) (*net.UDPConn, error) {
	t.Helper()
	return listenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, spec)
}

func TestUDPSecondBindWithoutReuseaddrFails(t *testing.T) {
	first, err := listenUDPOnPort(t, parseUDPSpec(t, "UDP4-LISTEN:0,bind=127.0.0.1"), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	port := first.LocalAddr().(*net.UDPAddr).Port
	second, err := listenUDPOnPort(t, parseUDPSpec(t, fmt.Sprintf("UDP4-LISTEN:%d,bind=127.0.0.1", port)), port)
	if err == nil {
		_ = second.Close()
		t.Fatal("second UDP-LISTEN without reuseaddr bound successfully")
	}
}

func TestUDPListenForkImpliesReuseaddr(t *testing.T) {
	first, err := listenUDPOnPort(t, parseUDPSpec(t, "UDP4-LISTEN:0,bind=127.0.0.1,fork"), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	port := first.LocalAddr().(*net.UDPAddr).Port
	second, err := listenUDPOnPort(t, parseUDPSpec(t, fmt.Sprintf("UDP4-LISTEN:%d,bind=127.0.0.1,fork", port)), port)
	if err != nil {
		t.Fatalf("second UDP-LISTEN,fork: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
}

func TestUDPForkReuseaddrZeroKeepsExclusive(t *testing.T) {
	first, err := listenUDPOnPort(t, parseUDPSpec(t, "UDP4-LISTEN:0,bind=127.0.0.1,fork,reuseaddr=0"), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	port := first.LocalAddr().(*net.UDPAddr).Port
	second, err := listenUDPOnPort(t, parseUDPSpec(t, fmt.Sprintf("UDP4-LISTEN:%d,bind=127.0.0.1,fork,reuseaddr=0", port)), port)
	if err == nil {
		_ = second.Close()
		t.Fatal("second UDP-LISTEN,fork,reuseaddr=0 bound successfully")
	}
}

func TestUDPRecvfromForkDoesNotImplyReuseaddr(t *testing.T) {
	first, err := listenUDPOnPort(t, parseUDPSpec(t, "UDP4-RECVFROM:0,bind=127.0.0.1,fork"), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	port := first.LocalAddr().(*net.UDPAddr).Port
	second, err := listenUDPOnPort(t, parseUDPSpec(t, fmt.Sprintf("UDP4-RECVFROM:%d,bind=127.0.0.1,fork", port)), port)
	if err == nil {
		_ = second.Close()
		t.Fatal("second UDP4-RECVFROM,fork bound successfully")
	}
}

func TestUDPRecvFromConnSetupStreamSetsockopt(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	// SO_BROADCAST is valid on UDP on Windows; SO_KEEPALIVE is not.
	spec, err := parse.ParseSpec(fmt.Sprintf("UDP4-LISTEN:0,setsockopt=%d:%d:1", syscall.SOL_SOCKET, syscall.SO_BROADCAST))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xio.SetupStream(spec, &udpRecvFromConn{uc: c}); err != nil {
		t.Fatalf("SetupStream on UDP session wrapper must not fail after raw apply: %v", err)
	}
}

func TestUDPListenMalformedRangeFailsOpen(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4-LISTEN:0,bind=127.0.0.1,range=X0000X7f000000:X0000xff000000")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	o, err := openUDP4Listen(context.Background(), spec, xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
	if o != nil {
		_ = o.Close()
		t.Fatal("UDP-LISTEN opened with uppercase hex range")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("malformed range took %v; want immediate open failure", elapsed)
	}
	if err == nil || !strings.Contains(err.Error(), "invalid hex") {
		t.Fatalf("openUDP4Listen err=%v want invalid hex", err)
	}
}
