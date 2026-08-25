package netopen

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/fileopen"
)

func useGlobal() *xio.Global {
	return &xio.Global{BlockSize: 8192, Log: logx.New(), Linger: 200 * time.Millisecond}
}

func startNetListenPIPE(t *testing.T, ctx context.Context, g *xio.Global, spec string) *xio.Opened {
	t.Helper()
	lo, err := xio.OpenChannel(ctx, parseChannel(t, spec), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	if lo.Listener == nil {
		_ = lo.Close()
		t.Fatal("listen did not return a listener")
	}
	go func() { _ = xio.RunOpened(ctx, lo, parseChannel(t, "PIPE"), g) }()
	return lo
}

func parseChannel(t *testing.T, spec string) parse.Channel {
	t.Helper()
	ch, err := parse.ParseChannel(spec)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

func echoConn(t *testing.T, st io.ReadWriter, payload []byte) {
	t.Helper()
	if d, ok := st.(interface{ SetDeadline(time.Time) error }); ok {
		_ = d.SetDeadline(time.Now().Add(3 * time.Second))
	}
	if _, err := st.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(st, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q want %q", got, payload)
	}
}

func TestTCP4ListenConnectUseCase(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	g := useGlobal()
	srv := startNetListenPIPE(t, ctx, g, "TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1")
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	cli, err := xio.OpenChannel(ctx, parseChannel(t, "TCP4:127.0.0.1:"+strconv.Itoa(port)+",connect-timeout=2"), xio.ModeRDWR, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	echoConn(t, cli.Stream, []byte("tcp-use"))
}

func TestUDP4SendtoRecvUseCase(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	g := useGlobal()
	recv, err := xio.OpenChannel(ctx, parseChannel(t, "UDP4-RECV:0,bind=127.0.0.1"), xio.ModeRead, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recv.Close() })
	la, ok := recv.Stream.(interface{ LocalAddr() net.Addr })
	if !ok {
		t.Fatal("UDP-RECV stream has no LocalAddr")
	}
	port := la.LocalAddr().(*net.UDPAddr).Port
	send, err := xio.OpenChannel(ctx, parseChannel(t, "UDP4-SENDTO:127.0.0.1:"+strconv.Itoa(port)), xio.ModeWrite, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = send.Close() })
	const payload = "udp-use"
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
		t.Fatalf("UDP-RECV got %q", got)
	}
}

func skipNoIPv6(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	_ = ln.Close()
}

func TestTCPListenConnectUnqualifiedUseCase(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv := startNetListenPIPE(t, ctx, useGlobal(), "TCP-LISTEN:0,reuseaddr,fork,bind=127.0.0.1")
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	cli, err := xio.OpenChannel(ctx, parseChannel(t, "TCP:127.0.0.1:"+strconv.Itoa(port)+",connect-timeout=2"), xio.ModeRDWR, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	echoConn(t, cli.Stream, []byte("tcp-generic"))
}

func TestTCP6ListenConnectUseCase(t *testing.T) {
	skipNoIPv6(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv := startNetListenPIPE(t, ctx, useGlobal(), "TCP6-LISTEN:0,reuseaddr,fork,bind=::1")
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	cli, err := xio.OpenChannel(ctx, parseChannel(t, "TCP6:[::1]:"+strconv.Itoa(port)+",connect-timeout=2"), xio.ModeRDWR, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	echoConn(t, cli.Stream, []byte("tcp6-use"))
}

func TestUDPListenConnectUnqualifiedUseCase(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv := startNetListenPIPE(t, ctx, useGlobal(), "UDP-LISTEN:0,reuseaddr,fork,bind=127.0.0.1")
	port := srv.Listener.Addr().(*net.UDPAddr).Port
	cli, err := xio.OpenChannel(ctx, parseChannel(t, "UDP:127.0.0.1:"+strconv.Itoa(port)), xio.ModeRDWR, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	echoConn(t, cli.Stream, []byte("udp-generic"))
}

func TestUDP4DatagramUseCase(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	recv, err := xio.OpenChannel(ctx, parseChannel(t, "UDP-RECV:0,bind=127.0.0.1"), xio.ModeRead, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recv.Close() })
	la, ok := recv.Stream.(interface{ LocalAddr() net.Addr })
	if !ok {
		t.Fatal("UDP-RECV stream has no LocalAddr")
	}
	port := la.LocalAddr().(*net.UDPAddr).Port
	send, err := xio.OpenChannel(ctx, parseChannel(t, "UDP4-DATAGRAM:127.0.0.1:"+strconv.Itoa(port)), xio.ModeWrite, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = send.Close() })
	const payload = "dgram-use"
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
		t.Fatalf("UDP-DATAGRAM got %q", got)
	}
}

func TestUDPSendtoRecvUnqualifiedUseCase(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	recv, err := xio.OpenChannel(ctx, parseChannel(t, "UDP-RECV:0,bind=127.0.0.1"), xio.ModeRead, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recv.Close() })
	la := recv.Stream.(interface{ LocalAddr() net.Addr })
	port := la.LocalAddr().(*net.UDPAddr).Port
	send, err := xio.OpenChannel(ctx, parseChannel(t, "UDP-SENDTO:127.0.0.1:"+strconv.Itoa(port)), xio.ModeWrite, useGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = send.Close() })
	const payload = "udp-sendto"
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
		t.Fatalf("UDP-SENDTO got %q", got)
	}
}
