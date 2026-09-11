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

func openNonForkUDP4Listen(t *testing.T, spec string, first ...[]byte) (*xio.Opened, *net.UDPConn) {
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
		o, err := openUDP4Listen(context.Background(), mustAddr(t, parsed), xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
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

	for _, packet := range first {
		if _, err := client.Write(packet); err != nil {
			t.Fatal(err)
		}
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

func TestUDPListenBoundBeforeFirstDatagram(t *testing.T) {
	parsed, err := parse.ParseSpec("UDP4-LISTEN:0,bind=127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	bound := make(chan net.Addr, 1)
	restore := xio.SetListenBoundTestHook(func(addr net.Addr) {
		select {
		case bound <- addr:
		default:
		}
	})
	t.Cleanup(restore)
	opened := make(chan error, 1)
	go func() {
		o, err := openUDP4Listen(ctx, mustAddr(t, parsed), xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
		if o != nil {
			_ = o.Close()
		}
		opened <- err
	}()
	select {
	case <-bound:
	case err := <-opened:
		t.Fatalf("open returned before bind: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("UDP-LISTEN did not bind")
	}
	select {
	case err := <-opened:
		t.Fatalf("open returned before the first datagram: %v", err)
	default:
	}
	cancel()
	select {
	case <-opened:
	case <-time.After(3 * time.Second):
		t.Fatal("open did not return after cancel")
	}
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

type shuttingStream interface {
	io.ReadWriteCloser
	ShutdownWrite() error
}

func openForkUDP4ListenStream(t *testing.T, spec string, first ...[]byte) (shuttingStream, *net.UDPConn) {
	t.Helper()
	parsed, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	o, err := openUDP4Listen(context.Background(), mustAddr(t, parsed), xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
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
	for _, packet := range first {
		if _, err := client.Write(packet); err != nil {
			t.Fatal(err)
		}
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

func TestUDPListenNonForkEmptyFirstNullEOF(t *testing.T) {
	o, _ := openNonForkUDP4Listen(t, "UDP4-LISTEN:0,bind=127.0.0.1,null-eof", nil)
	got, err := readStreamTimeout(t, o.Stream, 2*time.Second)
	if !errors.Is(err, io.EOF) || got != "" {
		t.Fatalf("got %q err=%v want EOF", got, err)
	}
}

func TestUDPListenEmptyOpenerIsEOF(t *testing.T) {
	// The payload after the empty opener is a sentinel: skipping the empty
	// packet would expose "hello" and fail instead of merely timing out.
	t.Run("nonfork", func(t *testing.T) {
		o, _ := openNonForkUDP4Listen(t, "UDP4-LISTEN:0,bind=127.0.0.1", nil, []byte("hello"))
		got, err := readStreamTimeout(t, o.Stream, 2*time.Second)
		if !errors.Is(err, io.EOF) || got != "" {
			t.Fatalf("got %q err=%v want EOF", got, err)
		}
	})

	t.Run("fork", func(t *testing.T) {
		st, _ := openForkUDP4ListenStream(t, "UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork", nil, []byte("hello"))
		got, err := readStreamTimeout(t, st, 2*time.Second)
		if !errors.Is(err, io.EOF) || got != "" {
			t.Fatalf("got %q err=%v want EOF", got, err)
		}
	})
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

func TestUDPListenForkConnectedEmptyDatagramIsEOF(t *testing.T) {
	// Send the payload and shut-null packet before Accept returns. The fork
	// handoff must keep both queued on the connected session socket.
	st, _ := openForkUDP4ListenStream(t, "UDP4-LISTEN:0,bind=127.0.0.1,reuseaddr,fork", []byte("hello"), nil)
	got, err := readStreamTimeout(t, st, 2*time.Second)
	if err != nil || got != "hello" {
		t.Fatalf("first got %q err=%v want hello", got, err)
	}
	got, err = readStreamTimeout(t, st, 2*time.Second)
	if !errors.Is(err, io.EOF) || got != "" {
		t.Fatalf("empty datagram got %q err=%v want EOF", got, err)
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
		o, err := openUDP4Recvfrom(context.Background(), mustAddr(t, parsed), xio.ModeRDWR, &xio.Global{BlockSize: 8192, Log: logx.New()})
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
