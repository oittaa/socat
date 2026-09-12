//go:build linux

package xio_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testcert"
	"github.com/oittaa/socat/internal/testutil"
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
	g = xio.NewSession(xio.Options{Experimental: true, BlockSize: 8192, Linger: 200 * time.Millisecond}, log)
	return ns, g
}

func separateNetNSGlobal(g *xio.Global) *xio.Global {
	opts := g.Options()
	opts.Experimental = true
	return xio.NewSession(opts, g.Log)
}

func connectNS(t *testing.T, ctx context.Context, g *xio.Global, spec string) *xio.Opened {
	t.Helper()
	wait, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var cli *xio.Opened
	var last error
	err := testutil.Until(wait, func() (bool, error) {
		ch, err := parse.ParseChannel(spec)
		if err != nil {
			return false, err
		}
		cli, last = xio.OpenChannel(ctx, ch, xio.ModeRDWR, g)
		return last == nil, nil
	})
	if err != nil {
		if last != nil {
			t.Fatalf("connect %s: %v", spec, last)
		}
		t.Fatalf("connect %s: %v", spec, err)
	}
	return cli
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

func TestFeatureNAMESPACES(t *testing.T) {
	if !xio.FeatureNAMESPACES {
		t.Fatal("WITH_NAMESPACES must be on for Linux")
	}
}
