package netopen

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func openNonForkUDP4Listen(t *testing.T, spec string, first []byte) (*xio.Opened, *net.UDPConn) {
	t.Helper()
	parsed, err := parse.ParseSpec(spec)
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
	go func() {
		o, err := openUDP4Listen(context.Background(), parsed, xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
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
		t.Fatal("UDP-LISTEN did not bind")
	}

	client, err := net.DialUDP("udp4", nil, addr.(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := client.Write(first); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-errc:
			t.Fatal(err)
		case o := <-opened:
			t.Cleanup(func() { _ = o.Close() })
			return o, client
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatal("UDP-LISTEN did not receive the first datagram")
	return nil, nil
}

func readStreamTimeout(t *testing.T, r io.Reader, timeout time.Duration) (string, error) {
	t.Helper()
	buf := make([]byte, 64)
	done := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := r.Read(buf)
		done <- struct {
			n   int
			err error
		}{n, err}
	}()
	select {
	case got := <-done:
		return string(buf[:got.n]), got.err
	case <-time.After(timeout):
		return "", errReadTimeout
	}
}

var errReadTimeout = errors.New("read timeout")

func waitEmptyUDP(t *testing.T, pc *net.UDPConn, timeout time.Duration) {
	t.Helper()
	if err := pc.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, _, err := pc.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("waiting for zero-length datagram: %v", err)
	}
	if n != 0 {
		t.Fatalf("got %q want empty datagram", buf[:n])
	}
}

func assertNoUDP(t *testing.T, pc *net.UDPConn, wait time.Duration) {
	t.Helper()
	if err := pc.SetReadDeadline(time.Now().Add(wait)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, _, err := pc.ReadFromUDP(buf)
	if err == nil {
		t.Fatalf("unexpected datagram %q", buf[:n])
	}
	if !xio.IsTimeoutErr(err) {
		t.Fatalf("err=%v want timeout", err)
	}
}

func TestUDPListenNonForkKeepsSamePeerSession(t *testing.T) {
	o, client := openNonForkUDP4Listen(t, "UDP4-LISTEN:0,bind=127.0.0.1", []byte("pkt1"))
	got, err := readStreamTimeout(t, o.Stream, 2*time.Second)
	if err != nil || got != "pkt1" {
		t.Fatalf("first=%q err=%v", got, err)
	}
	if _, err := client.Write([]byte("pkt2")); err != nil {
		t.Fatal(err)
	}
	got, err = readStreamTimeout(t, o.Stream, 2*time.Second)
	if err != nil || got != "pkt2" {
		t.Fatalf("second=%q err=%v want pkt2", got, err)
	}
	got, err = readStreamTimeout(t, o.Stream, 80*time.Millisecond)
	if !errors.Is(err, errReadTimeout) {
		t.Fatalf("LISTEN returned %q err=%v after two datagrams; want to keep waiting", got, err)
	}
}

func TestUDPListenNonForkIgnoresWrongPeer(t *testing.T) {
	o, client := openNonForkUDP4Listen(t, "UDP4-LISTEN:0,bind=127.0.0.1", []byte("mine"))
	got, err := readStreamTimeout(t, o.Stream, 2*time.Second)
	if err != nil || got != "mine" {
		t.Fatalf("first=%q err=%v", got, err)
	}

	other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	dst := client.RemoteAddr().(*net.UDPAddr)
	if _, err := other.WriteToUDP([]byte("intruder"), dst); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("again")); err != nil {
		t.Fatal(err)
	}
	got, err = readStreamTimeout(t, o.Stream, 2*time.Second)
	if err != nil || got != "again" {
		t.Fatalf("second=%q err=%v want again (wrong peer must be dropped)", got, err)
	}
}

func TestUDPRecvfromNonForkStillEOFAfterFirst(t *testing.T) {
	parsed, err := parse.ParseSpec("UDP4-RECVFROM:0,bind=127.0.0.1")
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
	go func() {
		o, err := openUDP4Recvfrom(context.Background(), parsed, xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
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
		t.Fatal("UDP-RECVFROM did not bind")
	}
	client, err := net.DialUDP("udp4", nil, addr.(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Write([]byte("once")); err != nil {
		t.Fatal(err)
	}
	var o *xio.Opened
	select {
	case err := <-errc:
		t.Fatal(err)
	case o = <-opened:
		t.Cleanup(func() { _ = o.Close() })
	case <-time.After(3 * time.Second):
		t.Fatal("UDP-RECVFROM did not receive")
	}
	got, err := readStreamTimeout(t, o.Stream, 2*time.Second)
	if err != nil || got != "once" {
		t.Fatalf("first=%q err=%v", got, err)
	}
	if _, err := client.Write([]byte("twice")); err != nil {
		t.Fatal(err)
	}
	got, err = readStreamTimeout(t, o.Stream, 2*time.Second)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("RECVFROM second read=%q err=%v want EOF", got, err)
	}
}

func TestUDPForkListenDistinctPeers(t *testing.T) {
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
	dst := o.Listener.Addr().(*net.UDPAddr)

	a, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, dst)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, dst)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })

	firstCh := startUDPAccept(o.Listener)
	if _, err := a.Write([]byte("from-a")); err != nil {
		t.Fatal(err)
	}
	sessA := waitUDPAccept(t, firstCh, 2*time.Second, "peer A")
	t.Cleanup(func() { _ = sessA.Close() })

	secondCh := startUDPAccept(o.Listener)
	if _, err := b.Write([]byte("from-b")); err != nil {
		t.Fatal(err)
	}
	sessB := waitUDPAccept(t, secondCh, 2*time.Second, "peer B")
	t.Cleanup(func() { _ = sessB.Close() })

	buf := make([]byte, 16)
	n, err := sessA.Read(buf)
	if err != nil || string(buf[:n]) != "from-a" {
		t.Fatalf("session A n=%d err=%v data=%q", n, err, buf[:n])
	}
	n, err = sessB.Read(buf)
	if err != nil || string(buf[:n]) != "from-b" {
		t.Fatalf("session B n=%d err=%v data=%q", n, err, buf[:n])
	}
}

func TestUDPConnectDefaultShutNull(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	port := peer.LocalAddr().(*net.UDPAddr).Port
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Connect(context.Background(), spec, xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if _, ok := o.Stream.(interface{ LocalAddr() net.Addr }); !ok {
		t.Fatalf("UDP-CONNECT stream %T lost LocalAddr after shut-null default", o.Stream)
	}
	if err := o.Stream.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	waitEmptyUDP(t, peer, 2*time.Second)
}

func TestUDPConnectShutNoneSendsNoDatagram(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	port := peer.LocalAddr().(*net.UDPAddr).Port
	spec, err := parse.ParseSpec("UDP4:127.0.0.1:" + strconv.Itoa(port) + ",shut-none")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Connect(context.Background(), spec, xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if err := o.Stream.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	assertNoUDP(t, peer, 150*time.Millisecond)
}

func TestUDPListenDefaultShutNull(t *testing.T) {
	o, client := openNonForkUDP4Listen(t, "UDP4-LISTEN:0,bind=127.0.0.1", []byte("hi"))
	if _, err := readStreamTimeout(t, o.Stream, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := o.Stream.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	waitEmptyUDP(t, client, 2*time.Second)
}

func TestUDPListenShutNoneSendsNoDatagram(t *testing.T) {
	o, client := openNonForkUDP4Listen(t, "UDP4-LISTEN:0,bind=127.0.0.1,shut-none", []byte("hi"))
	if _, err := readStreamTimeout(t, o.Stream, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := o.Stream.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	assertNoUDP(t, client, 150*time.Millisecond)
}

func TestUDPSendtoAndDatagramHaveNoImplicitShutNull(t *testing.T) {
	for _, typ := range []string{"UDP4-SENDTO", "UDP4-DATAGRAM"} {
		t.Run(typ, func(t *testing.T) {
			peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = peer.Close() })
			port := peer.LocalAddr().(*net.UDPAddr).Port
			spec, err := parse.ParseSpec(typ + ":127.0.0.1:" + strconv.Itoa(port))
			if err != nil {
				t.Fatal(err)
			}
			var o *xio.Opened
			if typ == "UDP4-SENDTO" {
				o, err = openUDP4Sendto(context.Background(), spec, xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
			} else {
				o, err = openUDP4Datagram(context.Background(), spec, xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = o.Close() })
			if err := o.Stream.ShutdownWrite(); err != nil {
				t.Fatal(err)
			}
			assertNoUDP(t, peer, 150*time.Millisecond)
		})
	}
}
