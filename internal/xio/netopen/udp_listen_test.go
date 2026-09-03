package netopen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestUDPNonForkAcceptTimeouts(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec string
		open func(context.Context, parse.Spec, xio.Mode, *xio.Global) (*xio.Opened, error)
	}{
		{name: "listen", spec: "UDP4-LISTEN:0,accept-timeout=0.03", open: openUDP4Listen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			g := &xio.Global{BlockSize: 8192, Log: logx.New()}
			start := time.Now()
			_, err = tc.open(context.Background(), spec, xio.ModeRDWR, g)
			if !errors.Is(err, xio.ErrAcceptTimeout) {
				t.Fatalf("error=%v want ErrAcceptTimeout", err)
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("accept timeout took %s", elapsed)
			}
		})
	}
}

func TestUDPForkListenerSurvivesReceiveTimeout(t *testing.T) {
	spec, err := parse.ParseSpec("UDP4-RECVFROM:0,fork,rcvtimeo=0.02")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := listenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, spec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ln := &udpForkListener{
		pc:         pc,
		network:    "udp4",
		laddr:      pc.LocalAddr().(*net.UDPAddr),
		spec:       spec,
		ctx:        ctx,
		rcvTimeout: 20 * time.Millisecond,
		oneShot:    true,
	}
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
	})

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, err := ln.Accept()
		accepted <- acceptResult{conn: conn, err: err}
	}()

	// Let more than one receive deadline expire before sending the packet.
	time.Sleep(75 * time.Millisecond)
	client, err := net.DialUDP("udp4", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	const payload = "after-timeout"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}

	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatal(result.err)
		}
		t.Cleanup(func() { _ = result.conn.Close() })
		buf := make([]byte, len(payload))
		if err := result.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		n, err := result.conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(buf[:n]); got != payload {
			t.Fatalf("payload=%q want %q", got, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not survive the receive timeout")
	}
}

func TestUDP4BindIPv6WildcardRejected(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		spec string
		open func(context.Context, parse.Spec, xio.Mode, *xio.Global) (*xio.Opened, error)
	}{
		{name: "listen", spec: "UDP4-LISTEN:0,bind=::,reuseaddr,accept-timeout=0.05", open: openUDP4Listen},
		{name: "sendto", spec: "UDP4-SENDTO:127.0.0.1:9,bind=::", open: openUDP4Sendto},
		{name: "connect", spec: "UDP4:127.0.0.1:9,bind=::", open: openUDP4Connect},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			o, err := tc.open(ctx, spec, xio.ModeRDWR, g)
			if err == nil {
				_ = o.Close()
				t.Fatal("bind=:: on UDP4 must not be rewritten to 0.0.0.0")
			}
			if !strings.Contains(err.Error(), "address family mismatch") {
				t.Fatalf("error=%v want address family mismatch", err)
			}
		})
	}
}

func TestUDPForkListenerOneShotFlag(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	for _, tc := range []struct {
		name    string
		spec    string
		open    func(context.Context, parse.Spec, xio.Mode, *xio.Global) (*xio.Opened, error)
		oneShot bool
	}{
		{name: "recvfrom", spec: "UDP4-RECVFROM:0,bind=127.0.0.1,reuseaddr,fork", open: openUDP4Recvfrom, oneShot: true},
		{name: "listen", spec: "UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork", open: openUDP4Listen, oneShot: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := parse.ParseSpec(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			o, err := tc.open(context.Background(), spec, xio.ModeRDWR, g)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = o.Close() })
			ln, ok := o.Listener.(interface{ oneShotMode() bool })
			if !ok {
				t.Fatalf("Listener type %T", o.Listener)
			}
			if got := ln.oneShotMode(); got != tc.oneShot {
				t.Fatalf("oneShot=%v want %v", got, tc.oneShot)
			}
		})
	}
}

func TestUDPSessionConnReadOneShotVsMulti(t *testing.T) {
	t.Run("recvfrom-one-shot", func(t *testing.T) {
		parent, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = parent.Close() })
		peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = peer.Close() })

		u := &udpSessionConn{
			pc:           parent,
			peer:         peer.LocalAddr().(*net.UDPAddr),
			first:        []byte("first"),
			firstPending: true,
			oneShot:      true,
		}
		buf := make([]byte, 16)
		n, err := u.Read(buf)
		if err != nil || string(buf[:n]) != "first" {
			t.Fatalf("first n=%d err=%v data=%q", n, err, buf[:n])
		}
		if _, err := peer.WriteToUDP([]byte("second"), parent.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
		n, err = u.Read(buf)
		if n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("one-shot second read n=%d err=%v want EOF", n, err)
		}
		if _, err := u.Write([]byte("ack")); err != nil {
			t.Fatal(err)
		}
		if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		n, _, err = peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("WriteToUDP reply: %v", err)
		}
		if got := string(buf[:n]); got != "ack" {
			t.Fatalf("reply=%q want ack", got)
		}
		_ = parent.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err = parent.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("parent lost the second datagram: %v", err)
		}
		if got := string(buf[:n]); got != "second" {
			t.Fatalf("parent read=%q want second", got)
		}
	})

	t.Run("listen-multi", func(t *testing.T) {
		server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = server.Close() })
		child, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = child.Close() })
		u := &udpSessionConn{conn: child, first: []byte("first"), firstPending: true, oneShot: false}
		buf := make([]byte, 16)
		n, err := u.Read(buf)
		if err != nil || string(buf[:n]) != "first" {
			t.Fatalf("first n=%d err=%v data=%q", n, err, buf[:n])
		}
		if _, err := server.WriteToUDP([]byte("second"), child.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
		if err := u.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		n, err = u.Read(buf)
		if err != nil {
			t.Fatalf("listen second read: %v", err)
		}
		if got := string(buf[:n]); got != "second" {
			t.Fatalf("second=%q want second", got)
		}
	})
}

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

func TestUDPForkRecvfromSecondDatagramReachesParent(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("UDP4-RECVFROM:0,bind=127.0.0.1,reuseaddr,fork")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Recvfrom(context.Background(), spec, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	ln := o.Listener

	client, err := net.DialUDP("udp4", nil, ln.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	firstCh := startUDPAccept(ln)
	if _, err := client.Write([]byte("pkt1")); err != nil {
		t.Fatal(err)
	}
	first := waitUDPAccept(t, firstCh, 2*time.Second, "first datagram")
	t.Cleanup(func() { _ = first.Close() })

	buf := make([]byte, 16)
	n, err := first.Read(buf)
	if err != nil || string(buf[:n]) != "pkt1" {
		t.Fatalf("first payload n=%d err=%v data=%q", n, err, buf[:n])
	}
	n, err = first.Read(buf)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("first child trailing read n=%d err=%v want EOF", n, err)
	}

	// Child timeouts must not poison the shared parent listener.
	if err := first.SetReadDeadline(time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Write([]byte("ack1")); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err = client.Read(buf)
	if err != nil {
		t.Fatalf("WriteToUDP reply: %v", err)
	}
	if got := string(buf[:n]); got != "ack1" {
		t.Fatalf("reply=%q want ack1", got)
	}

	// Keep the first child open: a connected child would steal this datagram.
	secondCh := startUDPAccept(ln)
	if _, err := client.Write([]byte("pkt2")); err != nil {
		t.Fatal(err)
	}
	second := waitUDPAccept(t, secondCh, 2*time.Second, "second same-peer datagram")
	t.Cleanup(func() { _ = second.Close() })
	n, err = second.Read(buf)
	if err != nil || string(buf[:n]) != "pkt2" {
		t.Fatalf("second payload n=%d err=%v data=%q", n, err, buf[:n])
	}

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	thirdCh := startUDPAccept(ln)
	if _, err := client.Write([]byte("pkt3")); err != nil {
		t.Fatal(err)
	}
	third := waitUDPAccept(t, thirdCh, 2*time.Second, "datagram after child Close")
	t.Cleanup(func() { _ = third.Close() })
	n, err = third.Read(buf)
	if err != nil || string(buf[:n]) != "pkt3" {
		t.Fatalf("third payload n=%d err=%v data=%q", n, err, buf[:n])
	}
}

func TestUDPForkListenSamePeerStaysInSession(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Listen(context.Background(), spec, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	ln := o.Listener

	client, err := net.DialUDP("udp4", nil, ln.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	firstCh := startUDPAccept(ln)
	if _, err := client.Write([]byte("pkt1")); err != nil {
		t.Fatal(err)
	}
	first := waitUDPAccept(t, firstCh, 2*time.Second, "listen first datagram")
	t.Cleanup(func() { _ = first.Close() })

	buf := make([]byte, 16)
	n, err := first.Read(buf)
	if err != nil || string(buf[:n]) != "pkt1" {
		t.Fatalf("first payload n=%d err=%v data=%q", n, err, buf[:n])
	}
	if _, err := first.Write([]byte("ack1")); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err = client.Read(buf)
	if err != nil || string(buf[:n]) != "ack1" {
		t.Fatalf("session reply n=%d err=%v data=%q", n, err, buf[:n])
	}
	if err := client.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	stolen := startUDPAccept(ln)
	if _, err := client.Write([]byte("pkt2")); err != nil {
		t.Fatal(err)
	}
	if err := first.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err = first.Read(buf)
	if err != nil || string(buf[:n]) != "pkt2" {
		t.Fatalf("existing session n=%d err=%v data=%q want pkt2", n, err, buf[:n])
	}
	select {
	case result := <-stolen:
		if result.err == nil {
			_ = result.conn.Close()
			t.Fatal("LISTEN Accept stole a same-peer datagram from the existing session")
		}
	case <-time.After(200 * time.Millisecond):
	}

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("pkt3")); err != nil {
		t.Fatal(err)
	}
	replacement := waitUDPAccept(t, stolen, 2*time.Second, "listen datagram after session close")
	t.Cleanup(func() { _ = replacement.Close() })
	n, err = replacement.Read(buf)
	if err != nil || string(buf[:n]) != "pkt3" {
		t.Fatalf("replacement session n=%d err=%v data=%q want pkt3", n, err, buf[:n])
	}
}

func TestUDPForkListenerAcceptTimeoutAborts(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork,accept-timeout=0.05")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Listen(context.Background(), spec, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	start := time.Now()
	_, err = o.Listener.Accept()
	if err == nil {
		t.Fatal("expected accept timeout")
	}
	if err != xio.ErrAcceptTimeout {
		t.Fatalf("err=%v want xio.ErrAcceptTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("accept-timeout took %s", elapsed)
	}
}

func TestUDPForkListenOpenedAcceptTimeoutAborts(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork,accept-timeout=0.05")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Listen(context.Background(), spec, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	start := time.Now()
	_, err = o.Listener.Accept()
	if err == nil {
		t.Fatal("expected accept timeout")
	}
	if err != xio.ErrAcceptTimeout {
		t.Fatalf("err=%v want xio.ErrAcceptTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("accept-timeout took %s", elapsed)
	}
}

func TestUDPForkListenOpenedSurvivesReceiveTimeout(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork,rcvtimeo=0.02")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Listen(context.Background(), spec, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	accepted := startUDPAccept(o.Listener)
	time.Sleep(75 * time.Millisecond)
	client, err := net.DialUDP("udp4", nil, o.Listener.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Write([]byte("after-timeout")); err != nil {
		t.Fatal(err)
	}
	conn := waitUDPAccept(t, accepted, 2*time.Second, "listen after rcvtimeo")
	t.Cleanup(func() { _ = conn.Close() })
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "after-timeout" {
		t.Fatalf("n=%d err=%v data=%q", n, err, buf[:n])
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

func TestUDPForkListenAcceptTimeoutRestartsAfterRejectedPeer(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork,range=10.0.0.1/32,accept-timeout=0.12")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Listen(context.Background(), spec, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	client, err := net.DialUDP("udp4", nil, o.Listener.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	done := make(chan error, 1)
	go func() {
		_, err := o.Listener.Accept()
		done <- err
	}()
	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		_, _ = client.Write([]byte("nope"))
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case err := <-done:
		t.Fatalf("accept returned while refused peers were still arriving: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestUDPForkRecvfromWriteDeadlineDoesNotPoisonParent(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("UDP4-RECVFROM:0,bind=127.0.0.1,reuseaddr,fork")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Recvfrom(context.Background(), spec, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	ln := o.Listener

	client, err := net.DialUDP("udp4", nil, ln.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	firstCh := startUDPAccept(ln)
	if _, err := client.Write([]byte("pkt1")); err != nil {
		t.Fatal(err)
	}
	first := waitUDPAccept(t, firstCh, 2*time.Second, "first datagram")
	t.Cleanup(func() { _ = first.Close() })
	buf := make([]byte, 16)
	n, err := first.Read(buf)
	if err != nil || string(buf[:n]) != "pkt1" {
		t.Fatalf("first n=%d err=%v data=%q", n, err, buf[:n])
	}
	if err := first.SetWriteDeadline(time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Write([]byte("late")); err == nil {
		t.Fatal("expected write deadline exceeded")
	}

	secondCh := startUDPAccept(ln)
	if _, err := client.Write([]byte("pkt2")); err != nil {
		t.Fatal(err)
	}
	second := waitUDPAccept(t, secondCh, 2*time.Second, "second datagram after child write deadline")
	t.Cleanup(func() { _ = second.Close() })
	n, err = second.Read(buf)
	if err != nil || string(buf[:n]) != "pkt2" {
		t.Fatalf("second n=%d err=%v data=%q", n, err, buf[:n])
	}
}

func TestUDPSessionConnShortReadDropsRemainder(t *testing.T) {
	u := &udpSessionConn{first: []byte("abcd"), firstPending: true, oneShot: true}
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

func TestUDPRecvFromConnShortReadDropsRemainder(t *testing.T) {
	u := &udpRecvFromConn{first: []byte("abcd"), firstPending: true, closeEOF: true}
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

func TestUDPSessionConnZeroLengthFirst(t *testing.T) {
	u := &udpSessionConn{firstPending: true, oneShot: true}
	n, err := u.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("zero-length first n=%d err=%v want EOF", n, err)
	}
}

func TestUDPSessionConnOneShotHidesSharedListener(t *testing.T) {
	parent, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Close() })
	u := &udpSessionConn{pc: parent, oneShot: true}
	if got := u.NetConn(); got != nil {
		t.Fatalf("oneShot NetConn=%v want nil", got)
	}
	handed := &udpSessionConn{pc: parent, ownsListen: true}
	if got := handed.NetConn(); got != parent {
		t.Fatalf("handoff NetConn=%v want listener", got)
	}
}

func TestUDPRecvFromConnZeroLengthFirst(t *testing.T) {
	u := &udpRecvFromConn{firstPending: true, closeEOF: true}
	n, err := u.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("zero-length first n=%d err=%v want EOF", n, err)
	}
}

func TestUDPListenForkShortReadDropsRemainder(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Listen(context.Background(), spec, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	client, err := net.DialUDP("udp4", nil, o.Listener.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	accepted := startUDPAccept(o.Listener)
	if _, err := client.Write([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	conn := waitUDPAccept(t, accepted, 2*time.Second, "listen first datagram")
	t.Cleanup(func() { _ = conn.Close() })

	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err != nil || n != 1 || buf[0] != 'a' {
		t.Fatalf("short read n=%d err=%v data=%q", n, err, buf[:n])
	}
	if err := conn.SetReadDeadline(time.Now().Add(80 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, err = conn.Read(buf)
	if n != 0 {
		t.Fatalf("remainder leaked n=%d data=%q", n, buf[:n])
	}
	if err == nil {
		t.Fatal("expected timeout or EOF after discarding the datagram remainder")
	}
}

func TestUDPForkRecvfromIgnoresAcceptTimeout(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("UDP4-RECVFROM:0,bind=127.0.0.1,reuseaddr,fork,accept-timeout=0.05")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Recvfrom(context.Background(), spec, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	accepted := startUDPAccept(o.Listener)
	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatalf("RECVFROM fork must not honor accept-timeout: %v", result.err)
		}
		_ = result.conn.Close()
		t.Fatalf("RECVFROM fork received an unexpected early connection from %v", result.conn.RemoteAddr())
	case <-time.After(150 * time.Millisecond):
	}

	client, err := net.DialUDP("udp4", nil, o.Listener.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Write([]byte("late")); err != nil {
		t.Fatal(err)
	}
	conn := waitUDPAccept(t, accepted, 2*time.Second, "recvfrom after ignored accept-timeout")
	t.Cleanup(func() { _ = conn.Close() })
	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "late" {
		t.Fatalf("n=%d err=%v data=%q", n, err, buf[:n])
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

func TestUDPSecondBindWithReuseaddrSucceeds(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux SO_REUSEADDR lets two UDP sockets share a port; Darwin/BSD need SO_REUSEPORT")
	}
	first, err := listenUDPOnPort(t, parseUDPSpec(t, "UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr"), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	port := first.LocalAddr().(*net.UDPAddr).Port
	second, err := listenUDPOnPort(t, parseUDPSpec(t, fmt.Sprintf("UDP4-LISTEN:%d,bind=127.0.0.1,reuseaddr", port)), port)
	if err != nil {
		t.Fatalf("second UDP-LISTEN,reuseaddr: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
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

func TestUDPListenForkReuseaddrZeroServesFirstClient(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec := parseUDPSpec(t, "UDP4-LISTEN:0,bind=127.0.0.1,fork,reuseaddr=0")
	o, err := openUDP4Listen(context.Background(), spec, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	ln := o.Listener

	client, err := net.DialUDP("udp4", nil, ln.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	accepted := startUDPAccept(ln)
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	sess := waitUDPAccept(t, accepted, 2*time.Second, "exclusive first datagram")
	t.Cleanup(func() { _ = sess.Close() })

	buf := make([]byte, 16)
	n, err := sess.Read(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("first payload n=%d err=%v data=%q", n, err, buf[:n])
	}
	if _, err := sess.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err = client.Read(buf)
	if err != nil || string(buf[:n]) != "pong" {
		t.Fatalf("echo n=%d err=%v data=%q", n, err, buf[:n])
	}

	if _, err := client.Write([]byte("ping2")); err != nil {
		t.Fatal(err)
	}
	if err := sess.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err = sess.Read(buf)
	if err != nil || string(buf[:n]) != "ping2" {
		t.Fatalf("second payload n=%d err=%v data=%q", n, err, buf[:n])
	}
	if _, err := sess.Write([]byte("pong2")); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err = client.Read(buf)
	if err != nil || string(buf[:n]) != "pong2" {
		t.Fatalf("second echo n=%d err=%v data=%q", n, err, buf[:n])
	}

	if runtime.GOOS == "windows" {
		return
	}
	second := startUDPAccept(ln)
	select {
	case result := <-second:
		if result.err == nil {
			_ = result.conn.Close()
			t.Fatal("second Accept succeeded before exclusive session closed")
		}
	case <-time.After(200 * time.Millisecond):
	}
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-second:
		if result.err == nil {
			_ = result.conn.Close()
			t.Fatal("second Accept produced a session after exclusive handoff")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second Accept still blocked after exclusive session Close")
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

func TestUDPRecvFromConnWrapCommonSetsockopt(t *testing.T) {
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
	if _, err := xio.WrapCommon(spec, &udpRecvFromConn{uc: c}); err != nil {
		t.Fatalf("WrapCommon on UDP session wrapper must not fail after raw apply: %v", err)
	}
}

func TestUDPListenPastSocketThenPrebind(t *testing.T) {
	spec, err := parse.ParseSpec(fmt.Sprintf(
		"UDP4-LISTEN:0,bind=127.0.0.1,setsockopt-socket=%d:%d:1,setsockopt-listen=%d:%d:0",
		syscall.SOL_SOCKET, syscall.SO_BROADCAST, syscall.SOL_SOCKET, syscall.SO_BROADCAST,
	))
	if err != nil {
		t.Fatal(err)
	}
	var values []int
	restore := xio.SetSockoptTestHook(func(c xio.SockoptCall) {
		if c.Opt == syscall.SO_BROADCAST {
			values = append(values, c.IntValue)
		}
	})
	defer restore()
	uc, err := listenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = uc.Close() })
	if len(values) != 2 || values[0] != 1 || values[1] != 0 {
		t.Fatalf("SO_BROADCAST values=%v want PASTSOCKET 1 then PREBIND 0", values)
	}
}

func TestUDPListenCancelsPeerFilterLookup(t *testing.T) {
	dns, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dns.Close() })
	queried := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 512)
		for {
			_, _, readErr := dns.ReadFrom(buf)
			if readErr != nil {
				return
			}
			select {
			case queried <- struct{}{}:
			default:
			}
		}
	}()

	spec, err := parse.ParseSpec("UDP4-LISTEN:0,bind=127.0.0.1,fork,range=cancel-udp.test:255.255.255.255,res-nsaddr=" + dns.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	errc := make(chan error, 1)
	go func() {
		o, openErr := openUDP4Listen(ctx, spec, xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
		if o != nil {
			_ = o.Close()
		}
		errc <- openErr
	}()

	select {
	case <-queried:
		cancel()
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("UDP peer filter did not query selected nameserver")
	}
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("openUDP4Listen error=%v want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("UDP-LISTEN ignored cancellation during peer-filter DNS")
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

func TestUDPListenAcceptTimeoutDoesNotIncludeRangeDNS(t *testing.T) {
	const dnsDelay = 300 * time.Millisecond
	dns := startARecordDNSDelayed(t, dnsDelay)
	spec, err := parse.ParseSpec("UDP4-LISTEN:0,bind=127.0.0.1,accept-timeout=0.1,range=udp-accept-timeout-range.test:255.255.255.255,res-nsaddr=" + dns.addr)
	if err != nil {
		t.Fatal(err)
	}

	bound := make(chan net.Addr, 1)
	restore := xio.SetListenBoundTestHook(func(addr net.Addr) {
		select {
		case bound <- addr:
		default:
		}
	})
	t.Cleanup(restore)

	errc := make(chan error, 1)
	opened := make(chan *xio.Opened, 1)
	start := time.Now()
	go func() {
		o, openErr := openUDP4Listen(context.Background(), spec, xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
		if openErr != nil {
			errc <- openErr
			return
		}
		opened <- o
	}()

	var addr net.Addr
	select {
	case addr = <-bound:
	case err := <-errc:
		t.Fatalf("UDP-LISTEN failed before bind: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("UDP-LISTEN did not bind")
	}

	client, err := net.DialUDP("udp4", nil, addr.(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Write([]byte("queued-before-range")); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errc:
		if errors.Is(err, xio.ErrAcceptTimeout) {
			t.Fatalf("accept-timeout consumed range DNS (%v after %s)", err, time.Since(start).Round(time.Millisecond))
		}
		t.Fatalf("openUDP4Listen: %v", err)
	case o := <-opened:
		t.Cleanup(func() { _ = o.Close() })
		if dns.queries.Load() == 0 {
			t.Fatal("range hostname was not resolved")
		}
		got := make([]byte, 64)
		n, readErr := o.EffectiveStream().Read(got)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(got[:n]) != "queued-before-range" {
			t.Fatalf("got %q", got[:n])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("UDP-LISTEN did not accept the queued peer")
	}
}
