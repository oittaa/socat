package all

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
)

// Tests in this file open addresses through xio.OpenChannel / xio.RunOpened
// and move bytes. They cover README and classic examples that unit tests
// previously only parsed.

func testGlobal() *xio.Global {
	return &xio.Global{BlockSize: 8192, Log: logx.New(), Linger: 200 * time.Millisecond}
}

// cloneGlobal is a per-process copy. OpenChannel and forkSession write peer
// fields on *Global, so a listener and a client must not share one.
func cloneGlobal(g *xio.Global) *xio.Global {
	if g == nil {
		return testGlobal()
	}
	return &xio.Global{
		Log:          g.Log,
		BlockSize:    g.BlockSize,
		Linger:       g.Linger,
		LeftToRight:  g.LeftToRight,
		RightToLeft:  g.RightToLeft,
		Experimental: g.Experimental,
		IPVersion:    g.IPVersion,
	}
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

func startListenPIPE(t *testing.T, ctx context.Context, g *xio.Global, listenSpec string) *xio.Opened {
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

// TestTCP4ListenPIPEEcho is classic `socat TCP4-LISTEN:port,reuseaddr,fork,bind=127.0.0.1 PIPE`.
func TestTCP4ListenPIPEEcho(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	srv := startListenPIPE(t, ctx, g, "TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1")
	cli := openClient(t, ctx, g, "TCP4:127.0.0.1:"+tcpPort(t, srv)+",connect-timeout=2")
	echoLive(t, streamOf(t, cli), []byte("tcp-hello"))
}

// TestTCP4ListenConnectEcho uses both the listen and connect openers, as in
// `socat - TCP4:127.0.0.1:port` talking to a TCP4-LISTEN peer.
func TestTCP4ListenConnectEcho(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	srv := startListenPIPE(t, ctx, g, "TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1")
	cli := openClient(t, ctx, g, "TCP4:127.0.0.1:"+tcpPort(t, srv)+",connect-timeout=2")
	echoLive(t, streamOf(t, cli), []byte("tcp4-connect"))
}

// TestTCPListenForwardsToTCP is `socat TCP4-LISTEN:front,fork TCP4:127.0.0.1:back`.
func TestTCPListenForwardsToTCP(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	back := startListenPIPE(t, ctx, g, "TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1")
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
	o, err := xio.OpenChannel(ctx, mustParse(t, fmt.Sprintf("FD:%d", int(r.Fd()))), xio.ModeRead, g)
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

func TestUDP4ListenPIPEEcho(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	srv := startListenPIPE(t, ctx, g, "UDP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1")
	cli := openClient(t, ctx, g, "UDP4:127.0.0.1:"+tcpPort(t, srv))
	echoLive(t, streamOf(t, cli), []byte("udp-hi"))
}

func TestUDP4SendtoToRecv(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	recv, err := xio.OpenChannel(ctx, mustParse(t, "UDP4-RECV:0,bind=127.0.0.1"), xio.ModeRead, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recv.Close() })
	port := localUDPPort(t, recv)
	send, err := xio.OpenChannel(ctx, mustParse(t, "UDP4-SENDTO:127.0.0.1:"+strconv.Itoa(port)), xio.ModeWrite, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = send.Close() })
	const payload = "syslog-hi"
	mustWrite(t, send.Stream, []byte(payload))
	if got := string(readFull(t, recv.Stream, len(payload))); got != payload {
		t.Fatalf("UDP-RECV got %q", got)
	}
}

func TestUDP4RecvfromForkEcho(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	srv := startListenPIPE(t, ctx, g, "UDP4-RECVFROM:0,bind=127.0.0.1,reuseaddr,fork")
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
	srv := startListenPIPE(t, ctx, g, "TLS-LISTEN:0,reuseaddr,fork,bind=127.0.0.1,verify=0,cert="+cert)
	cli := openClient(t, ctx, g, "TLS:127.0.0.1:"+tcpPort(t, srv)+",verify=0,connect-timeout=2")
	echoLive(t, streamOf(t, cli), []byte("tls-hello"))
}

func TestOPENSSLListenAliasEcho(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	cert := listenCert(t)
	srv := startListenPIPE(t, ctx, g, "OPENSSL-LISTEN:0,reuseaddr,fork,bind=127.0.0.1,verify=0,cert="+cert)
	cli := openClient(t, ctx, g, "OPENSSL:127.0.0.1:"+tcpPort(t, srv)+",verify=0,connect-timeout=2")
	echoLive(t, streamOf(t, cli), []byte("openssl-alias"))
}

// TestTLSListenForwardsToTCP is the README "encrypt a legacy TCP service" server:
// TLS-LISTEN → TCP:127.0.0.1:backend.
func TestTLSListenForwardsToTCP(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	back := startListenPIPE(t, ctx, g, "TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1")
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
	tlsSrv := startListenPIPE(t, ctx, g, "TLS-LISTEN:0,reuseaddr,fork,bind=127.0.0.1,verify=0,cert="+cert)
	front := startListenRight(t, ctx, g,
		"TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1",
		"TLS:127.0.0.1:"+tcpPort(t, tlsSrv)+",verify=0,connect-timeout=2")
	cli := openClient(t, ctx, g, "TCP4:127.0.0.1:"+tcpPort(t, front)+",connect-timeout=2")
	echoLive(t, streamOf(t, cli), []byte("plain-to-tls"))
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
