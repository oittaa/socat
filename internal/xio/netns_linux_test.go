//go:build linux

package xio_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testcert"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func skipUnlessNetNS(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("need root for netns=")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip not available")
	}
}

func setupNetNS(t *testing.T) (ns string, g *xio.Global) {
	t.Helper()
	skipUnlessNetNS(t)
	ns = fmt.Sprintf("socat-test-%d-%d", os.Getpid(), time.Now().UnixNano()%1e6)
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("ip", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v %s", strings.Join(args, " "), err, out)
		}
	}
	_ = exec.Command("ip", "netns", "del", ns).Run()
	run("netns", "add", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	run("netns", "exec", ns, "ip", "-4", "addr", "add", "dev", "lo", "127.0.0.1/8")
	run("netns", "exec", ns, "ip", "link", "set", "lo", "up")
	log := logx.New()
	log.SetLevel(logx.Error)
	g = &xio.Global{Log: log, Experimental: true, BlockSize: 8192, Linger: 200 * time.Millisecond}
	return ns, g
}

func separateNetNSGlobal(g *xio.Global) *xio.Global {
	return &xio.Global{
		Log:          g.Log,
		Experimental: true,
		BlockSize:    g.BlockSize,
		Linger:       g.Linger,
	}
}

func startListenPIPE(t *testing.T, ctx context.Context, g *xio.Global, spec string) {
	t.Helper()
	ls, err := parse.ParseChannel(spec)
	if err != nil {
		t.Fatal(err)
	}
	pipe, err := parse.ParseChannel("PIPE")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		lo, err := xio.OpenChannel(ctx, ls, xio.ModeRDWR, g)
		if err != nil {
			return
		}
		_ = xio.RunOpened(ctx, lo, pipe, g)
	}()
	time.Sleep(80 * time.Millisecond)
}

func connectNS(t *testing.T, ctx context.Context, g *xio.Global, spec string) *xio.Opened {
	t.Helper()
	var cli *xio.Opened
	deadline := time.Now().Add(3 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		ch, err := parse.ParseChannel(spec)
		if err != nil {
			t.Fatal(err)
		}
		cli, err = xio.OpenChannel(ctx, ch, xio.ModeRDWR, g)
		if err == nil {
			return cli
		}
		last = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("connect %s: %v", spec, last)
	return nil
}

func echoRW(t *testing.T, st io.ReadWriter, payload []byte) {
	t.Helper()
	if _, err := st.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if d, ok := st.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(time.Now().Add(2 * time.Second))
	}
	n, err := st.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf[:n], bytes.TrimSpace(payload)) && !bytes.Contains(buf[:n], payload) {
		t.Fatalf("got %q", buf[:n])
	}
}

func TestNetNSTCPEcho(t *testing.T) {
	ns, g := setupNetNS(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := 18000 + os.Getpid()%1000
	startListenPIPE(t, ctx, g, fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,fork,bind=127.0.0.1,netns=%s", port, ns))
	cli := connectNS(t, ctx, separateNetNSGlobal(g), fmt.Sprintf("TCP4:127.0.0.1:%d,netns=%s", port, ns))
	defer func() { _ = cli.Close() }()
	echoRW(t, cli.EffectiveStream(), []byte("netns-tcp\n"))
}

func TestNetNSTCPConnectFork(t *testing.T) {
	ns, g := setupNetNS(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := 19000 + os.Getpid()%1000
	startListenPIPE(t, ctx, g, fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,fork,bind=127.0.0.1,netns=%s", port, ns))

	ch, err := parse.ParseChannel(fmt.Sprintf("TCP4:127.0.0.1:%d,fork,netns=%s", port, ns))
	if err != nil {
		t.Fatal(err)
	}
	lo, err := xio.OpenChannel(ctx, ch, xio.ModeRDWR, separateNetNSGlobal(g))
	if err != nil {
		t.Fatal(err)
	}
	if lo.Kind != xio.KindDial || lo.Dial == nil {
		t.Fatalf("kind %v dial=%v", lo.Kind, lo.Dial != nil)
	}

	// Default-ns connect must fail: the listener exists only in ns.
	d := net.Dialer{Timeout: 200 * time.Millisecond}
	if c, err := d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
		_ = c.Close()
		t.Fatal("listener visible in default namespace")
	}

	// Stored Dial must run inside WithNetNS or this connect fails.
	c, err := lo.Dial(ctx)
	if err != nil {
		t.Fatalf("fork Dial in netns: %v", err)
	}
	_ = c.Close()
}

func TestNetNSUDPEcho(t *testing.T) {
	ns, g := setupNetNS(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := 20000 + os.Getpid()%1000
	startListenPIPE(t, ctx, g, fmt.Sprintf("UDP4-LISTEN:%d,reuseaddr,bind=127.0.0.1,netns=%s", port, ns))
	cli := connectNS(t, ctx, separateNetNSGlobal(g), fmt.Sprintf("UDP4:127.0.0.1:%d,netns=%s", port, ns))
	defer func() { _ = cli.Close() }()
	echoRW(t, cli.EffectiveStream(), []byte("netns-udp\n"))
}

func TestNetNSTLSEcho(t *testing.T) {
	ns, g := setupNetNS(t)
	cert, err := testcert.WriteTempListenCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := 21000 + os.Getpid()%1000
	startListenPIPE(t, ctx, g, fmt.Sprintf("TLS-LISTEN:%d,reuseaddr,fork,bind=127.0.0.1,verify=0,cert=%s,netns=%s", port, cert, ns))
	cli := connectNS(t, ctx, separateNetNSGlobal(g), fmt.Sprintf("TLS:127.0.0.1:%d,verify=0,commonname=localhost,netns=%s", port, ns))
	defer func() { _ = cli.Close() }()
	echoRW(t, cli.EffectiveStream(), []byte("netns-tls\n"))
}

func TestNetNSQUICEcho(t *testing.T) {
	ns, g := setupNetNS(t)
	cert, err := testcert.WriteTempListenCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := 22000 + os.Getpid()%1000
	startListenPIPE(t, ctx, g, fmt.Sprintf("QUIC-LISTEN:%d,reuseaddr,fork,bind=127.0.0.1,verify=0,cert=%s,netns=%s", port, cert, ns))
	cli := connectNS(t, ctx, separateNetNSGlobal(g), fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0,commonname=localhost,netns=%s", port, ns))
	defer func() { _ = cli.Close() }()
	echoRW(t, cli.EffectiveStream(), []byte("netns-quic"))
}

func TestWithNetNSRestoreOnPanic(t *testing.T) {
	ns, g := setupNetNS(t)
	before, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	s := parse.Spec{Options: []parse.Option{{Name: "netns", Has: true, Value: ns}}}
	func() {
		defer func() { _ = recover() }()
		_ = xio.WithNetNS(s, g, func() error {
			panic("netns-test")
		})
	}()
	after, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("namespace not restored after panic: before=%s after=%s", before, after)
	}
}
