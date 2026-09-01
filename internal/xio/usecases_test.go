package xio_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testcert"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

// Tests in this file open addresses through xio.OpenChannel / xio.RunOpened
// and move bytes. They cover README and classic examples that unit tests
// previously only parsed. Live-path echoes for a given address and option
// set live here; opener packages keep tests that assert package-private
// behavior.

// cloneGlobal is a per-process copy. OpenChannel and forkSession write peer
// fields on *Global, so a listener and a client must not share one.
func cloneGlobal(g *xio.Global) *xio.Global {
	if g == nil {
		g = testGlobal()
	}
	cg := &xio.Global{
		Log:          g.Log,
		BlockSize:    g.BlockSize,
		Linger:       g.Linger,
		LeftToRight:  g.LeftToRight,
		RightToLeft:  g.RightToLeft,
		Experimental: g.Experimental,
		IPVersion:    g.IPVersion,
	}
	if cg.Log == nil {
		cg.Log = logx.New()
	}
	if cg.BlockSize == 0 {
		cg.BlockSize = 8192
	}
	if cg.Linger == 0 {
		cg.Linger = 200 * time.Millisecond
	}
	return cg
}

func mustParse(t *testing.T, spec string) parse.Channel {
	t.Helper()
	ch, err := parse.ParseChannel(spec)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

func listenerPort(t *testing.T, o *xio.Opened) int {
	t.Helper()
	if o == nil || o.Listener == nil {
		t.Fatal("listen address did not return a listener (use fork)")
	}
	switch addr := o.Listener.Addr().(type) {
	case *net.TCPAddr:
		return addr.Port
	case *net.UDPAddr:
		return addr.Port
	default:
		t.Fatalf("listener addr %T", o.Listener.Addr())
		return 0
	}
}

func startListenRight(t *testing.T, ctx context.Context, g *xio.Global, listenSpec, rightSpec string) *xio.Opened {
	t.Helper()
	g = cloneGlobal(g)
	lo, err := xio.OpenChannel(ctx, mustParse(t, listenSpec), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	if lo.Listener == nil {
		_ = lo.Close()
		t.Fatal("listen address did not return a listener (use fork)")
	}
	right := mustParse(t, rightSpec)
	go func() { _ = xio.RunOpened(ctx, lo, right, g) }()
	return lo
}

func startForkListenPIPE(t *testing.T, ctx context.Context, g *xio.Global, listenSpec string) *xio.Opened {
	t.Helper()
	return startListenRight(t, ctx, g, listenSpec, "PIPE")
}

func openClient(t *testing.T, ctx context.Context, g *xio.Global, spec string) *xio.Opened {
	t.Helper()
	g = cloneGlobal(g)
	ch := mustParse(t, spec)
	deadline := time.Now().Add(3 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		o, err := xio.OpenChannel(ctx, ch, xio.ModeRDWR, g)
		if err == nil {
			t.Cleanup(func() { _ = o.Close() })
			return o
		}
		last = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("open %s: %v", spec, last)
	return nil
}

func setRWDeadline(rw any, d time.Duration) {
	if sd, ok := rw.(interface{ SetDeadline(time.Time) error }); ok {
		_ = sd.SetDeadline(time.Now().Add(d))
		return
	}
	if rd, ok := rw.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = rd.SetReadDeadline(time.Now().Add(d))
	}
	if wd, ok := rw.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = wd.SetWriteDeadline(time.Now().Add(d))
	}
}

func mustWrite(t *testing.T, w io.Writer, p []byte) {
	t.Helper()
	setRWDeadline(w, 3*time.Second)
	if _, err := w.Write(p); err != nil {
		t.Fatal(err)
	}
}

func readFull(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	setRWDeadline(r, 3*time.Second)
	buf := make([]byte, n)
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(r, buf)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
		return buf
	case <-time.After(4 * time.Second):
		t.Fatal("timed out reading")
		return nil
	}
}

func readAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	setRWDeadline(r, 3*time.Second)
	done := make(chan struct {
		b   []byte
		err error
	}, 1)
	go func() {
		b, err := io.ReadAll(r)
		done <- struct {
			b   []byte
			err error
		}{b, err}
	}()
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatal(got.err)
		}
		return got.b
	case <-time.After(4 * time.Second):
		t.Fatal("timed out reading to EOF")
		return nil
	}
}

func echoLive(t *testing.T, st io.ReadWriter, payload []byte) {
	t.Helper()
	mustWrite(t, st, payload)
	if got := readFull(t, st, len(payload)); string(got) != string(payload) {
		t.Fatalf("echo got %q want %q", got, payload)
	}
}

func streamOf(t *testing.T, o *xio.Opened) io.ReadWriter {
	t.Helper()
	if o.Stream == nil {
		t.Fatal("opened address has no stream")
	}
	return o.Stream
}

func listenCert(t *testing.T) string {
	t.Helper()
	p, err := testcert.WriteTempListenCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func tcpPort(t *testing.T, o *xio.Opened) string {
	t.Helper()
	return strconv.Itoa(listenerPort(t, o))
}

func sockaddrPort(t *testing.T, addr net.Addr) int {
	t.Helper()
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.Port
	case *net.UDPAddr:
		return a.Port
	default:
		t.Fatalf("listen addr %T", addr)
		return 0
	}
}

func listenBoundPort(t *testing.T) (<-chan net.Addr, func()) {
	t.Helper()
	bound := make(chan net.Addr, 1)
	restore := xio.SetListenBoundTestHook(func(addr net.Addr) {
		select {
		case bound <- addr:
		default:
		}
	})
	return bound, restore
}

func waitBoundPort(t *testing.T, bound <-chan net.Addr, failed <-chan error) int {
	t.Helper()
	select {
	case addr := <-bound:
		port := sockaddrPort(t, addr)
		if port == 0 {
			t.Fatal("listen bound port 0")
		}
		return port
	case err := <-failed:
		if err != nil {
			t.Fatal(err)
		}
		t.Fatal("listen returned before bind")
	case <-time.After(4 * time.Second):
		t.Fatal("listen did not bind")
	}
	return 0
}

func localUDPPort(t *testing.T, o *xio.Opened) int {
	t.Helper()
	type localAddrer interface{ LocalAddr() net.Addr }
	if la, ok := o.Stream.(localAddrer); ok {
		if addr, ok := la.LocalAddr().(*net.UDPAddr); ok {
			return addr.Port
		}
		t.Fatalf("UDP local addr %T", la.LocalAddr())
	}
	t.Fatal("UDP stream has no LocalAddr")
	return 0
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func skipNoIPv6(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	_ = ln.Close()
}

func waitDialTCP4(t *testing.T, port int) net.Conn {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(3 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp4", addr, 150*time.Millisecond)
		if err == nil {
			t.Cleanup(func() { _ = c.Close() })
			return c
		}
		last = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("dial %s: %v", addr, last)
	return nil
}

// TestTCP4ListenPIPEEcho is classic `socat TCP4-LISTEN:port,reuseaddr,fork,bind=127.0.0.1 PIPE`
// plus a TCP4 connect client.
func TestTCP4ListenPIPEEcho(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	srv := startForkListenPIPE(t, ctx, g, "TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1")
	cli := openClient(t, ctx, g, "TCP4:127.0.0.1:"+tcpPort(t, srv)+",connect-timeout=2")
	echoLive(t, streamOf(t, cli), []byte("tcp-hello"))
}

// TestTCPListenForwardsToTCP is `socat TCP4-LISTEN:front,fork TCP4:127.0.0.1:back`.
func TestTCPListenForwardsToTCP(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	back := startForkListenPIPE(t, ctx, g, "TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1")
	front := startListenRight(t, ctx, g,
		"TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1",
		"TCP4:127.0.0.1:"+tcpPort(t, back)+",connect-timeout=2")
	cli := openClient(t, ctx, g, "TCP4:127.0.0.1:"+tcpPort(t, front)+",connect-timeout=2")
	echoLive(t, streamOf(t, cli), []byte("forwarded"))
}

func TestTEXTToCREATE(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	g.LeftToRight = true
	path := filepath.Join(t.TempDir(), "text.out")
	left := mustParse(t, "TEXT:hello-text")
	right := mustParse(t, "CREATE:"+path)
	if err := xio.Run(ctx, left, right, g); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello-text" {
		t.Fatalf("CREATE got %q", got)
	}
}

func TestCREATEThenOPEN(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	path := filepath.Join(t.TempDir(), "file.bin")
	const payload = "file-bytes"
	w, err := xio.OpenChannel(ctx, mustParse(t, "CREATE:"+path), xio.ModeWrite, g)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, w.Stream, []byte(payload))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := xio.OpenChannel(ctx, mustParse(t, "OPEN:"+path), xio.ModeRead, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if got := string(readAll(t, r.Stream)); got != payload {
		t.Fatalf("OPEN got %q", got)
	}
}

func TestGOPENCreatesAndAppends(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	path := filepath.Join(t.TempDir(), "gopen.bin")
	w, err := xio.OpenChannel(ctx, mustParse(t, "GOPEN:"+path), xio.ModeWrite, g)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, w.Stream, []byte("ab"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	appendW, err := xio.OpenChannel(ctx, mustParse(t, "GOPEN:"+path), xio.ModeWrite, g)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, appendW.Stream, []byte("cd"))
	if err := appendW.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abcd" {
		t.Fatalf("GOPEN append got %q want abcd", got)
	}
}

func TestAnonymousPIPEEcho(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	o, err := xio.OpenChannel(ctx, mustParse(t, "PIPE"), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	echoLive(t, streamOf(t, o), []byte("pipe-echo"))
}

func TestDualOpenCreate(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	dir := t.TempDir()
	inPath := filepath.Join(dir, "in")
	outPath := filepath.Join(dir, "out")
	if err := os.WriteFile(inPath, []byte("from-in"), 0o644); err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenChannel(ctx, mustParse(t, "OPEN:"+inPath+"!!CREATE:"+outPath), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(readAll(t, o.Stream)); got != "from-in" {
		t.Fatalf("dual read %q", got)
	}
	mustWrite(t, o.Stream, []byte("to-out"))
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "to-out" {
		t.Fatalf("dual write %q", got)
	}
}

func TestFDReadsPipe(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})
	nfd := duplicateFDNumber(t, r)
	o, err := xio.OpenChannel(ctx, mustParse(t, fmt.Sprintf("FD:%d", nfd)), xio.ModeRead, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	mustWrite(t, w, []byte("fd-bytes"))
	_ = w.Close()
	if got := string(readAll(t, o.Stream)); got != "fd-bytes" {
		t.Fatalf("FD got %q", got)
	}
}

func TestTCPListenForkFDEndCloseServesTwoClients(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	g.LeftToRight = true
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})
	nfd := duplicateFDNumber(t, w)
	_ = w.Close()
	srv := startListenRight(t, ctx, g,
		"TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1",
		fmt.Sprintf("FD:%d,end-close", nfd))
	addr := "TCP:127.0.0.1:" + tcpPort(t, srv) + ",connect-timeout=2"
	for _, payload := range []string{"first", "second"} {
		cli := openClient(t, ctx, g, addr)
		mustWrite(t, cli.Stream, []byte(payload))
		if err := cli.Stream.ShutdownWrite(); err != nil {
			t.Fatal(err)
		}
		if got := string(readFull(t, r, len(payload))); got != payload {
			t.Fatalf("got %q want %q", got, payload)
		}
		_ = cli.Close()
	}
}

func TestUDP4ListenPIPEEcho(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	srv := startForkListenPIPE(t, ctx, g, "UDP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1")
	cli := openClient(t, ctx, g, "UDP4:127.0.0.1:"+tcpPort(t, srv))
	echoLive(t, streamOf(t, cli), []byte("udp-hi"))
}

func TestUDP4ListenForkReuseaddrZeroPIPEEcho(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	srv := startForkListenPIPE(t, ctx, g, "UDP4-LISTEN:0,fork,reuseaddr=0,bind=127.0.0.1")
	cli := openClient(t, ctx, g, "UDP4:127.0.0.1:"+tcpPort(t, srv))
	echoLive(t, streamOf(t, cli), []byte("udp-exclusive-hi"))
}

func TestUDPSendtoToRecv(t *testing.T) {
	for _, sendType := range []string{"UDP4-SENDTO", "UDP-SENDTO"} {
		t.Run(sendType, func(t *testing.T) {
			ctx, g := testCtx(t), testGlobal()
			recv, err := xio.OpenChannel(ctx, mustParse(t, "UDP4-RECV:0,bind=127.0.0.1"), xio.ModeRead, g)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = recv.Close() })
			port := localUDPPort(t, recv)
			send, err := xio.OpenChannel(ctx, mustParse(t, sendType+":127.0.0.1:"+strconv.Itoa(port)), xio.ModeWrite, cloneGlobal(g))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = send.Close() })
			const payload = "syslog-hi"
			mustWrite(t, send.Stream, []byte(payload))
			if got := string(readFull(t, recv.Stream, len(payload))); got != payload {
				t.Fatalf("UDP-RECV got %q", got)
			}
		})
	}
}

// TestUDP4RecvfromReply is one-shot UDP-RECVFROM (no fork): wait for a datagram
// and reply to the sender. fork+PIPE needs socketpair, which Windows does not have.
func TestUDP4RecvfromReply(t *testing.T) {
	ctx := testCtx(t)
	spec := mustParse(t, "UDP4-RECVFROM:0,bind=127.0.0.1,reuseaddr=0")
	opened := make(chan *xio.Opened, 1)
	errCh := make(chan error, 1)
	bound, restore := listenBoundPort(t)
	defer restore()
	go func() {
		o, err := xio.OpenChannel(ctx, spec, xio.ModeRDWR, cloneGlobal(nil))
		if err != nil {
			errCh <- err
			return
		}
		opened <- o
	}()
	port := waitBoundPort(t, bound, errCh)
	cli, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	const payload = "recvfrom-hi"
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
			t.Fatal("UDP-RECVFROM open timed out")
		}
	}
	t.Cleanup(func() { _ = o.Close() })
	if got := string(readFull(t, o.Stream, len(payload))); got != payload {
		t.Fatalf("UDP-RECVFROM got %q", got)
	}
	mustWrite(t, o.Stream, []byte(payload))
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, err := cli.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != payload {
		t.Fatalf("UDP-RECVFROM reply %q", buf[:n])
	}
}

func TestUDP4RecvfromForkEcho(t *testing.T) {
	if !xio.FeatureSOCKETPAIR {
		t.Skip("RECVFROM,fork echo uses socketpair")
	}
	ctx, g := testCtx(t), testGlobal()
	srv := startForkListenPIPE(t, ctx, g, "UDP4-RECVFROM:0,bind=127.0.0.1,reuseaddr,fork")
	cli, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: listenerPort(t, srv)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	const payload = "recvfrom-hi"
	mustWrite(t, cli, []byte(payload))
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, err := cli.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != payload {
		t.Fatalf("UDP-RECVFROM echo %q", buf[:n])
	}
}

func TestTLSListenPIPEEcho(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	cert := listenCert(t)
	srv := startForkListenPIPE(t, ctx, g, "TLS-LISTEN:0,reuseaddr,fork,bind=127.0.0.1,verify=0,cert="+cert)
	cli := openClient(t, ctx, g, "TLS:127.0.0.1:"+tcpPort(t, srv)+",verify=0,connect-timeout=2")
	echoLive(t, streamOf(t, cli), []byte("tls-hello"))
}

func TestOPENSSLListenAliasEcho(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	cert := listenCert(t)
	srv := startForkListenPIPE(t, ctx, g, "OPENSSL-LISTEN:0,reuseaddr,fork,bind=127.0.0.1,verify=0,cert="+cert)
	cli := openClient(t, ctx, g, "OPENSSL:127.0.0.1:"+tcpPort(t, srv)+",verify=0,connect-timeout=2")
	echoLive(t, streamOf(t, cli), []byte("openssl-alias"))
}

func TestTLSLAliasAndTLSConnectAlias(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	cert := listenCert(t)
	srv := startForkListenPIPE(t, ctx, g, "TLS-L:0,reuseaddr,fork,bind=127.0.0.1,verify=0,cert="+cert)
	cli := openClient(t, ctx, g, "TLS-CONNECT:127.0.0.1:"+tcpPort(t, srv)+",verify=0,connect-timeout=2")
	echoLive(t, streamOf(t, cli), []byte("tls-aliases"))
}

func TestOPENSSLCertificateAliasEcho(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	cert := listenCert(t)
	srv := startForkListenPIPE(t, ctx, g, "OPENSSL-LISTEN:0,reuseaddr,fork,bind=127.0.0.1,openssl-verify=0,openssl-certificate="+cert)
	cli := openClient(t, ctx, g, "OPENSSL:127.0.0.1:"+tcpPort(t, srv)+",openssl-verify=0,connect-timeout=2")
	echoLive(t, streamOf(t, cli), []byte("tls-cert-alias"))
}

// TestTLSListenForwardsToTCP is the README "encrypt a legacy TCP service" server:
// TLS-LISTEN → TCP:127.0.0.1:backend.
func TestTLSListenForwardsToTCP(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	back := startForkListenPIPE(t, ctx, g, "TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1")
	cert := listenCert(t)
	front := startListenRight(t, ctx, g,
		"TLS-LISTEN:0,reuseaddr,fork,bind=127.0.0.1,verify=0,cert="+cert,
		"TCP4:127.0.0.1:"+tcpPort(t, back)+",connect-timeout=2")
	cli := openClient(t, ctx, g, "TLS:127.0.0.1:"+tcpPort(t, front)+",verify=0,connect-timeout=2")
	echoLive(t, streamOf(t, cli), []byte("legacy-tls"))
}

// TestTCPListenForwardsToTLS is the README client-side wrapper:
// TCP-LISTEN → TLS:server (plain local app, TLS on the wire).
func TestTCPListenForwardsToTLS(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	cert := listenCert(t)
	tlsSrv := startForkListenPIPE(t, ctx, g, "TLS-LISTEN:0,reuseaddr,fork,bind=127.0.0.1,verify=0,cert="+cert)
	front := startListenRight(t, ctx, g,
		"TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1",
		"TLS:127.0.0.1:"+tcpPort(t, tlsSrv)+",verify=0,connect-timeout=2")
	cli := openClient(t, ctx, g, "TCP4:127.0.0.1:"+tcpPort(t, front)+",connect-timeout=2")
	echoLive(t, streamOf(t, cli), []byte("plain-to-tls"))
}

// TestTCPListenConnectUnqualified is the README/netcat shape people type:
// `socat TCP-LISTEN:port,reuseaddr,fork,bind=127.0.0.1 PIPE` plus `TCP:host:port`.
func TestTCPListenConnectUnqualified(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	srv := startForkListenPIPE(t, ctx, g, "TCP-LISTEN:0,reuseaddr,fork,bind=127.0.0.1")
	cli := openClient(t, ctx, g, "TCP:127.0.0.1:"+tcpPort(t, srv)+",connect-timeout=2")
	echoLive(t, streamOf(t, cli), []byte("tcp-unqualified"))
}

func TestTCPLAliasAndTCPConnectAlias(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	srv := startForkListenPIPE(t, ctx, g, "TCP-L:0,reuseaddr,fork,bind=127.0.0.1")
	cli := openClient(t, ctx, g, "TCP-CONNECT:127.0.0.1:"+tcpPort(t, srv)+",connect-timeout=2")
	echoLive(t, streamOf(t, cli), []byte("tcp-aliases"))
}

func TestTCP6ListenConnectEcho(t *testing.T) {
	skipNoIPv6(t)
	ctx, g := testCtx(t), testGlobal()
	srv := startForkListenPIPE(t, ctx, g, "TCP6-LISTEN:0,reuseaddr,fork,bind=::1")
	cli := openClient(t, ctx, g, "TCP6:[::1]:"+tcpPort(t, srv)+",connect-timeout=2")
	echoLive(t, streamOf(t, cli), []byte("tcp6-hello"))
}

// TestTCPListenDumpsToCREATE is `socat -u TCP-LISTEN:port,reuseaddr,fork CREATE:file`.
func TestTCPListenDumpsToCREATE(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	g.LeftToRight = true
	path := filepath.Join(t.TempDir(), "dump.bin")
	srv := startListenRight(t, ctx, g,
		"TCP-LISTEN:0,reuseaddr,fork,bind=127.0.0.1",
		"CREATE:"+path)
	cli := openClient(t, ctx, g, "TCP:127.0.0.1:"+tcpPort(t, srv)+",connect-timeout=2")
	mustWrite(t, cli.Stream, []byte("dumped"))
	if err := cli.Stream.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, err := os.ReadFile(path)
		if err == nil && string(got) == "dumped" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	got, _ := os.ReadFile(path)
	t.Fatalf("CREATE dump got %q want dumped", got)
}

// TestPIPEToTCPListenFork is listen on the right address:
// `socat PIPE TCP-LISTEN:port,reuseaddr,fork` (runForkListenRight).
func TestPIPEToTCPListenFork(t *testing.T) {
	ctx := testCtx(t)
	left, err := xio.OpenChannel(ctx, mustParse(t, "PIPE"), xio.ModeRDWR, cloneGlobal(nil))
	if err != nil {
		t.Fatal(err)
	}
	bound, restore := listenBoundPort(t)
	defer restore()
	errCh := make(chan error, 1)
	go func() {
		errCh <- xio.RunOpened(ctx, left, mustParse(t, "TCP-LISTEN:0,reuseaddr,fork,bind=127.0.0.1"), cloneGlobal(nil))
	}()
	port := waitBoundPort(t, bound, errCh)
	cli := openClient(t, ctx, testGlobal(), fmt.Sprintf("TCP:127.0.0.1:%d,connect-timeout=2", port))
	echoLive(t, streamOf(t, cli), []byte("right-listen"))
}

// TestTCPListenNoForkEcho is one-shot `socat TCP-LISTEN:port,reuseaddr PIPE`
// (no fork): OpenChannel accepts a single connection, then RunOpened transfers.
func TestTCPListenNoForkEcho(t *testing.T) {
	ctx := testCtx(t)
	opened := make(chan *xio.Opened, 1)
	errCh := make(chan error, 1)
	bound, restore := listenBoundPort(t)
	defer restore()
	go func() {
		o, err := xio.OpenChannel(ctx, mustParse(t, "TCP-LISTEN:0,reuseaddr,bind=127.0.0.1"), xio.ModeRDWR, cloneGlobal(nil))
		if err != nil {
			errCh <- err
			return
		}
		opened <- o
	}()
	port := waitBoundPort(t, bound, errCh)
	c := waitDialTCP4(t, port)
	var lo *xio.Opened
	select {
	case lo = <-opened:
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(4 * time.Second):
		t.Fatal("TCP-LISTEN accept timed out")
	}
	go func() { _ = xio.RunOpened(ctx, lo, mustParse(t, "PIPE"), cloneGlobal(nil)) }()
	echoLive(t, c, []byte("nofork"))
}

func TestTCPListenRangeAllowsLoopback(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	srv := startForkListenPIPE(t, ctx, g, "TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1,range=127.0.0.0/8")
	cli := openClient(t, ctx, g, "TCP4:127.0.0.1:"+tcpPort(t, srv)+",connect-timeout=2")
	echoLive(t, streamOf(t, cli), []byte("in-range"))
}

func TestTCPListenRangeRejects(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	srv := startForkListenPIPE(t, ctx, g, "TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1,range=10.0.0.0/8")
	c, err := net.DialTimeout("tcp4", "127.0.0.1:"+tcpPort(t, srv), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_, _ = c.Write([]byte("nope"))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, rerr := c.Read(buf)
	if n > 0 {
		t.Fatalf("range-rejected peer read %q", buf[:n])
	}
	if rerr == nil {
		t.Fatal("range-rejected peer: expected EOF or error")
	}
}

func TestTCPConnectRetryWaitsForListener(t *testing.T) {
	var last error
	for attempt := 1; attempt <= 3; attempt++ {
		err := tcpConnectRetryOnce(t)
		if err == nil {
			return
		}
		last = err
		t.Logf("attempt %d: %v", attempt, err)
	}
	t.Fatalf("retry connect failed: %v", last)
}

func tcpConnectRetryOnce(t *testing.T) error {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	success := false
	defer func() {
		if !success {
			cancel()
		} else {
			t.Cleanup(cancel)
		}
	}()

	done := make(chan *xio.Opened, 1)
	errCh := make(chan error, 1)
	go func() {
		o, err := xio.OpenChannel(ctx, mustParse(t, fmt.Sprintf("TCP:127.0.0.1:%d,retry=50,interval=0.05,connect-timeout=1", port)), xio.ModeRDWR, cloneGlobal(nil))
		if err != nil {
			errCh <- err
			return
		}
		done <- o
	}()
	time.Sleep(150 * time.Millisecond)
	srv, err := xio.OpenChannel(ctx, mustParse(t, fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,fork,bind=127.0.0.1", port)), xio.ModeRDWR, cloneGlobal(nil))
	if err != nil {
		return fmt.Errorf("listen %d: %w", port, err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	go func() { _ = xio.RunOpened(ctx, srv, mustParse(t, "PIPE"), cloneGlobal(nil)) }()

	var cli *xio.Opened
	select {
	case cli = <-done:
		t.Cleanup(func() { _ = cli.Close() })
	case err := <-errCh:
		return err
	case <-time.After(6 * time.Second):
		return fmt.Errorf("retry connect timed out")
	}
	echoLive(t, streamOf(t, cli), []byte("retried"))
	success = true
	return nil
}

func TestTCPConnectReadbytes(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	srv := startForkListenPIPE(t, ctx, g, "TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1")
	cli := openClient(t, ctx, g, "TCP4:127.0.0.1:"+tcpPort(t, srv)+",readbytes=4,connect-timeout=2")
	mustWrite(t, cli.Stream, []byte("hello"))
	if got := string(readFull(t, cli.Stream, 4)); got != "hell" {
		t.Fatalf("readbytes got %q want hell", got)
	}
}

func TestFILEAliasRoundtrip(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	path := filepath.Join(t.TempDir(), "alias.bin")
	const payload = "file-alias"
	w, err := xio.OpenChannel(ctx, mustParse(t, "CREATE:"+path), xio.ModeWrite, g)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, w.Stream, []byte(payload))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := xio.OpenChannel(ctx, mustParse(t, "FILE:"+path), xio.ModeRead, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if got := string(readAll(t, r.Stream)); got != payload {
		t.Fatalf("FILE got %q", got)
	}
}

func TestECHOAliasPIPE(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	o, err := xio.OpenChannel(ctx, mustParse(t, "ECHO"), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	echoLive(t, streamOf(t, o), []byte("echo-alias"))
}

func TestCREATAliasCREATE(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	g.LeftToRight = true
	path := filepath.Join(t.TempDir(), "creat.out")
	if err := xio.Run(ctx, mustParse(t, "TEXT:creat-ok"), mustParse(t, "CREAT:"+path), g); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "creat-ok" {
		t.Fatalf("CREAT got %q", got)
	}
}

func TestUDPListenConnectUnqualified(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	srv := startForkListenPIPE(t, ctx, g, "UDP-LISTEN:0,reuseaddr,fork,bind=127.0.0.1")
	cli := openClient(t, ctx, g, "UDP:127.0.0.1:"+tcpPort(t, srv))
	echoLive(t, streamOf(t, cli), []byte("udp-unqual"))
}

func TestUDP4DatagramToRecv(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	recv, err := xio.OpenChannel(ctx, mustParse(t, "UDP-RECV:0,bind=127.0.0.1"), xio.ModeRead, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recv.Close() })
	port := localUDPPort(t, recv)
	send, err := xio.OpenChannel(ctx, mustParse(t, "UDP4-DATAGRAM:127.0.0.1:"+strconv.Itoa(port)), xio.ModeWrite, cloneGlobal(g))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = send.Close() })
	const payload = "dgram-hi"
	mustWrite(t, send.Stream, []byte(payload))
	if got := string(readFull(t, recv.Stream, len(payload))); got != payload {
		t.Fatalf("UDP-DATAGRAM got %q", got)
	}
}

func TestTCPConnectCRNL(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- []byte("accept:" + err.Error())
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, len("helo\r\n"))
		if _, err := io.ReadFull(c, buf); err != nil {
			got <- []byte("read:" + err.Error())
			return
		}
		got <- append([]byte(nil), buf...)
	}()

	ctx, g := testCtx(t), testGlobal()
	port := ln.Addr().(*net.TCPAddr).Port
	cli := openClient(t, ctx, g, fmt.Sprintf("TCP4:127.0.0.1:%d,crnl,connect-timeout=2", port))
	mustWrite(t, cli.Stream, []byte("helo\n"))
	select {
	case b := <-got:
		if string(b) != "helo\r\n" {
			t.Fatalf("peer got %q want CRLF", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for crnl write")
	}
}

func TestTCPConnectCR(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- []byte("accept:" + err.Error())
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, len("helo\r"))
		if _, err := io.ReadFull(c, buf); err != nil {
			got <- []byte("read:" + err.Error())
			return
		}
		got <- append([]byte(nil), buf...)
	}()

	ctx, g := testCtx(t), testGlobal()
	port := ln.Addr().(*net.TCPAddr).Port
	cli := openClient(t, ctx, g, fmt.Sprintf("TCP4:127.0.0.1:%d,cr,connect-timeout=2", port))
	mustWrite(t, cli.Stream, []byte("helo\n"))
	select {
	case b := <-got:
		if string(b) != "helo\r" {
			t.Fatalf("peer got %q want CR", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for cr write")
	}
}
