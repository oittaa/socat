package netopen

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
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

	if _, err := client.Write(first); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		t.Fatal(err)
	case o := <-opened:
		t.Cleanup(func() { _ = o.Close() })
		return o, client
	case <-time.After(3 * time.Second):
		t.Fatal("UDP-LISTEN did not receive the first datagram")
	}
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

func TestUDPConnectEmptyDatagramIsEOF(t *testing.T) {
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
	local, ok := o.Stream.(interface{ LocalAddr() net.Addr })
	if !ok {
		t.Fatalf("UDP-CONNECT stream %T has no LocalAddr", o.Stream)
	}
	la, ok := local.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("LocalAddr %T want *net.UDPAddr", local.LocalAddr())
	}
	if _, err := peer.WriteToUDP(nil, la); err != nil {
		t.Fatal(err)
	}
	got, err := readStreamTimeout(t, o.Stream, 2*time.Second)
	if !errors.Is(err, io.EOF) || got != "" {
		t.Fatalf("got %q err=%v want EOF", got, err)
	}
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

type shuttingStream interface {
	io.ReadWriteCloser
	ShutdownWrite() error
}

func openUDP4ConnectPeer(t *testing.T, opts string) (shuttingStream, *net.UDPConn) {
	t.Helper()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	spec := "UDP4:127.0.0.1:" + strconv.Itoa(peer.LocalAddr().(*net.UDPAddr).Port)
	if opts != "" {
		spec += "," + opts
	}
	parsed, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Connect(context.Background(), parsed, xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o.Stream, peer
}

func openForkUDP4ListenStream(t *testing.T, spec string, first []byte) (shuttingStream, *net.UDPConn) {
	t.Helper()
	parsed, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Listen(context.Background(), parsed, xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.WrapDial == nil {
		t.Fatal("WrapDial is nil")
	}
	client, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, o.Listener.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ch := startUDPAccept(o.Listener)
	if _, err := client.Write(first); err != nil {
		t.Fatal(err)
	}
	sess := waitUDPAccept(t, ch, 2*time.Second, "fork session")
	st, err := o.WrapDial(sess)
	if err != nil {
		_ = sess.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, client
}

func writeUDPReply(t *testing.T, pc *net.UDPConn, p []byte, addr *net.UDPAddr) {
	t.Helper()
	if pc.RemoteAddr() != nil {
		if _, err := pc.Write(p); err != nil {
			t.Fatal(err)
		}
		return
	}
	if _, err := pc.WriteToUDP(p, addr); err != nil {
		t.Fatal(err)
	}
}

func checkUDPShutPolicy(t *testing.T, stream shuttingStream, peer *net.UDPConn, emptyPacket, writeAfter, readAfter bool) {
	t.Helper()
	if _, err := stream.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, addr, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("got %q want hello", buf[:n])
	}
	if err := stream.ShutdownWrite(); err != nil {
		t.Fatalf("ShutdownWrite: %v", err)
	}
	if emptyPacket {
		waitEmptyUDP(t, peer, 2*time.Second)
	} else {
		assertNoUDP(t, peer, 150*time.Millisecond)
	}
	if writeAfter {
		if _, err := stream.Write([]byte("after")); err != nil {
			t.Fatalf("write after shutdown: %v", err)
		}
		if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		n, _, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("after: %v", err)
		}
		if string(buf[:n]) != "after" {
			t.Fatalf("got %q want after", buf[:n])
		}
	} else if _, err := stream.Write([]byte("after")); err == nil {
		t.Fatal("write after shut-down succeeded")
	}
	if !readAfter {
		return
	}
	writeUDPReply(t, peer, []byte("more"), addr)
	got, err := readStreamTimeout(t, stream, 2*time.Second)
	if err != nil || got != "more" {
		t.Fatalf("read after shutdown=%q err=%v want more", got, err)
	}
}

func TestUDPExplicitShutPolicies(t *testing.T) {
	cases := []struct {
		name        string
		opts        string
		emptyPacket bool
		writeAfter  bool
		readAfter   bool
	}{
		{name: "shut-none", opts: "shut-none", writeAfter: true, readAfter: true},
		{name: "shut-down", opts: "shut-down", readAfter: true},
		{name: "shut-close", opts: "shut-close"},
		{name: "shut-null", opts: "shut-null", emptyPacket: true, writeAfter: true, readAfter: true},
		{name: "shut-null,shut-down", opts: "shut-null,shut-down", readAfter: true},
		{name: "shut-down,shut-null", opts: "shut-down,shut-null", emptyPacket: true, writeAfter: true, readAfter: true},
	}
	for _, tc := range cases {
		t.Run("connect/"+tc.name, func(t *testing.T) {
			stream, peer := openUDP4ConnectPeer(t, tc.opts)
			checkUDPShutPolicy(t, stream, peer, tc.emptyPacket, tc.writeAfter, tc.readAfter)
		})
		t.Run("listen/"+tc.name, func(t *testing.T) {
			o, client := openNonForkUDP4Listen(t, "UDP4-LISTEN:0,bind=127.0.0.1,"+tc.opts, []byte("hi"))
			got, err := readStreamTimeout(t, o.Stream, 2*time.Second)
			if err != nil || got != "hi" {
				t.Fatalf("opener=%q err=%v", got, err)
			}
			checkUDPShutPolicy(t, o.Stream, client, tc.emptyPacket, tc.writeAfter, tc.readAfter)
		})
		t.Run("fork/"+tc.name, func(t *testing.T) {
			spec := "UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork," + tc.opts
			if rejectUDPListenForkShutDown(t, spec) {
				return
			}
			st, client := openForkUDP4ListenStream(t, spec, []byte("hi"))
			got, err := readStreamTimeout(t, st, 2*time.Second)
			if err != nil || got != "hi" {
				t.Fatalf("opener=%q err=%v", got, err)
			}
			checkUDPShutPolicy(t, st, client, tc.emptyPacket, tc.writeAfter, tc.readAfter)
		})
	}
	t.Run("fork-handoff/shut-down", func(t *testing.T) {
		spec := "UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr=0,fork,shut-down"
		if rejectUDPListenForkShutDown(t, spec) {
			return
		}
		st, client := openForkUDP4ListenStream(t, spec, []byte("hi"))
		got, err := readStreamTimeout(t, st, 2*time.Second)
		if err != nil || got != "hi" {
			t.Fatalf("opener=%q err=%v", got, err)
		}
		checkUDPShutPolicy(t, st, client, false, false, true)
	})
}

func rejectUDPListenForkShutDown(t *testing.T, spec string) bool {
	t.Helper()
	parsed, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	if !udpForkSharesListenSocket() || !xio.ShutDownSelected(parsed) {
		return false
	}
	o, err := openUDP4Listen(context.Background(), parsed, xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
	if o != nil {
		_ = o.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "UDP-LISTEN,fork,shut-down") {
		t.Fatalf("err=%v want UDP-LISTEN,fork,shut-down not supported", err)
	}
	return true
}

func TestUDPListenNonForkEmptyFirstNullEOF(t *testing.T) {
	o, _ := openNonForkUDP4Listen(t, "UDP4-LISTEN:0,bind=127.0.0.1,null-eof", nil)
	got, err := readStreamTimeout(t, o.Stream, 2*time.Second)
	if !errors.Is(err, io.EOF) || got != "" {
		t.Fatalf("got %q err=%v want EOF", got, err)
	}
}

func TestUDPListenConnectedEmptyDatagramIsEOF(t *testing.T) {
	o, client := openNonForkUDP4Listen(t, "UDP4-LISTEN:0,bind=127.0.0.1", []byte("hello"))
	got, err := readStreamTimeout(t, o.Stream, 2*time.Second)
	if err != nil || got != "hello" {
		t.Fatalf("first got %q err=%v want hello", got, err)
	}
	if _, err := client.Write(nil); err != nil {
		t.Fatal(err)
	}
	got, err = readStreamTimeout(t, o.Stream, 2*time.Second)
	if !errors.Is(err, io.EOF) || got != "" {
		t.Fatalf("empty datagram got %q err=%v want EOF", got, err)
	}
}

func TestUDPListenForkEmptyFirstNullEOF(t *testing.T) {
	st, _ := openForkUDP4ListenStream(t, "UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork,null-eof", nil)
	got, err := readStreamTimeout(t, st, 2*time.Second)
	if !errors.Is(err, io.EOF) || got != "" {
		t.Fatalf("got %q err=%v want EOF", got, err)
	}
}

func TestUDPListenForkShutDownRejectedWhenShared(t *testing.T) {
	for _, spec := range []string{
		"UDP4-LISTEN:0,bind=127.0.0.1,fork,shut-down",
		"UDP4-LISTEN:0,bind=127.0.0.1,fork,shut-null,shut-down",
		"UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr=0,fork,shut-down",
		"UDP4-LISTEN:0,bind=127.0.0.1,fork,shut=down",
	} {
		t.Run(spec, func(t *testing.T) {
			parsed, err := parse.ParseSpec(spec)
			if err != nil {
				t.Fatal(err)
			}
			o, err := openUDP4Listen(context.Background(), parsed, xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
			if udpForkSharesListenSocket() {
				if o != nil {
					_ = o.Close()
				}
				if err == nil || !strings.Contains(err.Error(), "UDP-LISTEN,fork,shut-down") {
					t.Fatalf("err=%v want UDP-LISTEN,fork,shut-down not supported", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = o.Close() })
		})
	}
}

func TestUDPRecvfromForkShutDownDoesNotExposeListener(t *testing.T) {
	parsed, err := parse.ParseSpec("UDP4-RECVFROM:0,bind=127.0.0.1,fork,shut-down")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Recvfrom(context.Background(), parsed, xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if o.WrapDial == nil {
		t.Fatal("WrapDial is nil")
	}
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
	stA, err := o.WrapDial(sessA)
	if err != nil {
		_ = sessA.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stA.Close() })
	got, err := readStreamTimeout(t, stA, 2*time.Second)
	if err != nil || got != "from-a" {
		t.Fatalf("session A=%q err=%v", got, err)
	}
	if err := stA.ShutdownWrite(); err == nil {
		t.Fatal("shut-down on UDP-RECVFROM,fork must not reach the shared listener")
	}

	secondCh := startUDPAccept(o.Listener)
	if _, err := b.Write([]byte("from-b")); err != nil {
		t.Fatal(err)
	}
	sessB := waitUDPAccept(t, secondCh, 2*time.Second, "peer B")
	stB, err := o.WrapDial(sessB)
	if err != nil {
		_ = sessB.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stB.Close() })
	if _, err := stB.Write([]byte("reply-b")); err != nil {
		t.Fatalf("session B write after peer A shut-down: %v", err)
	}
	if err := b.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, _, err := b.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("session B reply: %v", err)
	}
	if string(buf[:n]) != "reply-b" {
		t.Fatalf("got %q want reply-b", buf[:n])
	}
}

func TestUDPListenIPvAnyConnectsIPv4Peer(t *testing.T) {
	parsed, err := parse.ParseSpec("UDP-LISTEN:0")
	if err != nil {
		t.Fatal(err)
	}
	g := &xio.Global{BlockSize: 8192, Log: logx.New(), IPVersion: xio.IPvAny}
	if netw := udpNetworkWithListenDefault(g, parsed); netw != "udp" {
		t.Fatalf("network=%q want udp", netw)
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
		o, err := openUDPListen(context.Background(), parsed, xio.ModeRDWR, g)
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
		t.Skipf("UDP-LISTEN IPvAny bind: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("UDP-LISTEN IPvAny did not bind")
	}
	laddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("addr type %T", addr)
	}
	if laddr.IP.To4() != nil {
		t.Skip("UDP-LISTEN with IPvAny bound IPv4, not dual-stack")
	}

	client, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: laddr.Port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Write([]byte("v4peer")); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errc:
		t.Fatalf("UDP-LISTEN IPvAny connect from IPv4 peer: %v", err)
	case o := <-opened:
		t.Cleanup(func() { _ = o.Close() })
		got, err := readStreamTimeout(t, o.Stream, 2*time.Second)
		if err != nil || got != "v4peer" {
			t.Fatalf("first=%q err=%v", got, err)
		}
		if _, err := o.Stream.Write([]byte("ack")); err != nil {
			t.Fatal(err)
		}
		if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 16)
		n, _, err := client.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("reply: %v", err)
		}
		if string(buf[:n]) != "ack" {
			t.Fatalf("got %q want ack", buf[:n])
		}
	case <-time.After(3 * time.Second):
		t.Skip("IPv4 datagram did not reach dual-stack UDP-LISTEN")
	}
}

func openUDP4RecvfromAfter(t *testing.T, spec string, send func(*net.UDPConn)) *xio.Opened {
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
	send(client)
	select {
	case err := <-errc:
		t.Fatal(err)
	case o := <-opened:
		t.Cleanup(func() { _ = o.Close() })
		return o
	case <-time.After(3 * time.Second):
		t.Fatal("UDP-RECVFROM did not receive")
	}
	return nil
}

func TestUDPRecvfromNonForkSkipsEmptyUnlessNullEOF(t *testing.T) {
	o := openUDP4RecvfromAfter(t, "UDP4-RECVFROM:0,bind=127.0.0.1", func(client *net.UDPConn) {
		if _, err := client.Write(nil); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write([]byte("payload")); err != nil {
			t.Fatal(err)
		}
	})
	got, err := readStreamTimeout(t, o.Stream, 2*time.Second)
	if err != nil || got != "payload" {
		t.Fatalf("got %q err=%v want payload", got, err)
	}
	got, err = readStreamTimeout(t, o.Stream, 2*time.Second)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("second=%q err=%v want EOF", got, err)
	}
}

func TestUDPRecvfromNonForkNullEOFEmptyEndsSession(t *testing.T) {
	o := openUDP4RecvfromAfter(t, "UDP4-RECVFROM:0,bind=127.0.0.1,null-eof", func(client *net.UDPConn) {
		if _, err := client.Write(nil); err != nil {
			t.Fatal(err)
		}
	})
	got, err := readStreamTimeout(t, o.Stream, 2*time.Second)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("empty null-eof got %q err=%v want EOF", got, err)
	}
}

func TestUDPRecvfromForkSkipsEmptyUnlessNullEOF(t *testing.T) {
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
	client, err := net.DialUDP("udp4", nil, o.Listener.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	accepted := startUDPAccept(o.Listener)
	if _, err := client.Write(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	conn := waitUDPAccept(t, accepted, 2*time.Second, "recvfrom nonempty after empty")
	t.Cleanup(func() { _ = conn.Close() })
	got, err := readStreamTimeout(t, conn, 2*time.Second)
	if err != nil || got != "payload" {
		t.Fatalf("got %q err=%v want payload", got, err)
	}
}

func TestUDPRecvfromForkNullEOFEmptyEndsSession(t *testing.T) {
	g := &xio.Global{BlockSize: 8192, Log: logx.New()}
	spec, err := parse.ParseSpec("UDP4-RECVFROM:0,bind=127.0.0.1,reuseaddr,fork,null-eof")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Recvfrom(context.Background(), spec, xio.ModeRDWR, g)
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
	if _, err := client.Write(nil); err != nil {
		t.Fatal(err)
	}
	conn := waitUDPAccept(t, accepted, 2*time.Second, "recvfrom null-eof empty")
	t.Cleanup(func() { _ = conn.Close() })
	got, err := readStreamTimeout(t, conn, 2*time.Second)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("empty null-eof got %q err=%v want EOF", got, err)
	}
}
