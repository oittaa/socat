package netopen

import (
	"context"
	"errors"
	"io"
	"net"
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

func TestUDP4BindIPv6WildcardNormalizes(t *testing.T) {
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
			if tc.name == "listen" {
				if !errors.Is(err, xio.ErrAcceptTimeout) {
					t.Fatalf("error=%v want ErrAcceptTimeout (bind=:: should normalize to 0.0.0.0)", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("open with bind=::: %v", err)
			}
			t.Cleanup(func() { _ = o.Close() })
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
			pc:      parent,
			peer:    peer.LocalAddr().(*net.UDPAddr),
			first:   []byte("first"),
			oneShot: true,
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
		u := &udpSessionConn{conn: child, first: []byte("first"), oneShot: false}
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
	ln, ok := o.Listener.(*udpForkListener)
	if !ok {
		t.Fatalf("Listener type %T", o.Listener)
	}

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
	child1, ok := first.(*udpSessionConn)
	if !ok {
		t.Fatalf("child type %T", first)
	}
	if child1.pc == nil || child1.conn != nil {
		t.Fatalf("RECVFROM child pc=%v conn=%v want shared parent and no connected socket", child1.pc != nil, child1.conn != nil)
	}

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
	child2, ok := second.(*udpSessionConn)
	if !ok {
		t.Fatalf("second child type %T", second)
	}
	if child2.pc == nil || child2.conn != nil {
		t.Fatalf("second RECVFROM child pc=%v conn=%v want shared parent", child2.pc != nil, child2.conn != nil)
	}
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
	u := &udpSessionConn{first: []byte("abcd"), oneShot: true}
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
	u := &udpRecvFromConn{first: []byte("abcd"), closeEOF: true}
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
		t.Fatal("RECVFROM fork Accept returned without a datagram")
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
