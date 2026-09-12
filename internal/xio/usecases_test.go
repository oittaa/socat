package xio_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testcert"
	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

// Tests in this file open addresses through xio.OpenChannel / xio.RunOpened
// and move bytes. They cover README and classic examples that unit tests
// previously only parsed. Live-path echoes for a given address and option
// set live here; opener packages keep tests that assert package-private
// behavior.

// cloneGlobal is a per-process copy. OpenChannel and ForkSession write peer
// fields on *Global, so a listener and a client must not share one.
func cloneGlobal(g *xio.Global) *xio.Global {
	if g == nil {
		g = testGlobal()
	}
	opts := *g.Options()
	if opts.BlockSize == 0 {
		opts.BlockSize = 8192
	}
	if opts.Linger == 0 {
		opts.Linger = 200 * time.Millisecond
	}
	log := g.Log
	if log == nil {
		log = logx.New()
	}
	cg := xio.NewSession(opts, log)
	cg.LogMixed = g.LogMixed
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
	if o == nil || o.Listener() == nil {
		t.Fatal("listen address did not return a listener (use fork)")
	}
	switch addr := o.Listener().Addr().(type) {
	case *net.TCPAddr:
		return addr.Port
	case *net.UDPAddr:
		return addr.Port
	default:
		t.Fatalf("listener addr %T", o.Listener().Addr())
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
	if lo.Listener() == nil {
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
	wait, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var last error
	var o *xio.Opened
	err := testutil.Until(wait, func() (bool, error) {
		o, last = xio.OpenChannel(ctx, ch, xio.ModeRDWR, g)
		return last == nil, nil
	})
	if err != nil {
		if last != nil {
			t.Fatalf("open %s: %v", spec, last)
		}
		t.Fatalf("open %s: %v", spec, err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o
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
	if o.Stream() == nil {
		t.Fatal("opened address has no stream")
	}
	return o.Stream()
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
	if la, ok := o.Stream().(localAddrer); ok {
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
	g.Options().LeftToRight = true
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

func TestAnonymousPIPEEcho(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	o, err := xio.OpenChannel(ctx, mustParse(t, "PIPE"), xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	echoLive(t, streamOf(t, o), []byte("pipe-echo"))
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

	var logBuf lockedBuf
	lg := logx.New()
	lg.SetOutput(&logBuf)
	lg.SetLevel(logx.Notice)
	g := cloneGlobal(nil)
	g.Log = lg

	done := make(chan *xio.Opened, 1)
	errCh := make(chan error, 1)
	go func() {
		o, err := xio.OpenChannel(ctx, mustParse(t, fmt.Sprintf("TCP:127.0.0.1:%d,retry=50,interval=0.05,connect-timeout=1", port)), xio.ModeRDWR, g)
		if err != nil {
			errCh <- err
			return
		}
		done <- o
	}()
	retryWait, retryCancel := context.WithTimeout(ctx, 3*time.Second)
	defer retryCancel()
	if err := testutil.Until(retryWait, func() (bool, error) {
		return strings.Contains(logBuf.String(), "retrying"), nil
	}); err != nil {
		return fmt.Errorf("connect did not retry: %v log=%s", err, logBuf.String())
	}
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

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *lockedBuf) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *lockedBuf) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

func TestTCPConnectReadbytes(t *testing.T) {
	ctx, g := testCtx(t), testGlobal()
	srv := startForkListenPIPE(t, ctx, g, "TCP4-LISTEN:0,reuseaddr,fork,bind=127.0.0.1")
	cli := openClient(t, ctx, g, "TCP4:127.0.0.1:"+tcpPort(t, srv)+",readbytes=4,connect-timeout=2")
	mustWrite(t, cli.Stream(), []byte("hello"))
	if got := string(readFull(t, cli.Stream(), 4)); got != "hell" {
		t.Fatalf("readbytes got %q want hell", got)
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
	g.Options().LeftToRight = true
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
	mustWrite(t, send.Stream(), []byte(payload))
	if got := string(readFull(t, recv.Stream(), len(payload))); got != payload {
		t.Fatalf("UDP-DATAGRAM got %q", got)
	}
}
