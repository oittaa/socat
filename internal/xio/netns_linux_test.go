//go:build linux

package xio_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
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

func TestNetNSTCPEcho(t *testing.T) {
	skipUnlessNetNS(t)
	ns := fmt.Sprintf("socat-test-%d", os.Getpid())
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("ip", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v %s", strings.Join(args, " "), err, out)
		}
	}
	_ = exec.Command("ip", "netns", "del", ns).Run()
	run("netns", "add", ns)
	defer func() { _ = exec.Command("ip", "netns", "del", ns).Run() }()
	run("netns", "exec", ns, "ip", "-4", "addr", "add", "dev", "lo", "127.0.0.1/8")
	run("netns", "exec", ns, "ip", "link", "set", "lo", "up")

	port := 18000 + os.Getpid()%1000
	left, err := parse.ParseChannel(fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,bind=127.0.0.1,netns=%s", port, ns))
	if err != nil {
		t.Fatal(err)
	}
	right, err := parse.ParseChannel("PIPE")
	if err != nil {
		t.Fatal(err)
	}
	log := logx.New()
	log.SetLevel(logx.Error)
	g := &xio.Global{Log: log, Experimental: true, BlockSize: 8192, Linger: 200 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- xio.Run(ctx, left, right, g) }()

	deadline := time.Now().Add(3 * time.Second)
	var cli *xio.Opened
	for time.Now().Before(deadline) {
		ch, err := parse.ParseChannel(fmt.Sprintf("TCP4:127.0.0.1:%d,netns=%s", port, ns))
		if err != nil {
			t.Fatal(err)
		}
		cli, err = xio.OpenChannel(ctx, ch, xio.ModeRDWR, g)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if cli == nil {
		cancel()
		t.Fatalf("connect failed; server: %v", <-errc)
	}
	defer func() { _ = cli.Close() }()
	st := cli.EffectiveStream()
	payload := []byte("netns-echo\n")
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
	if !bytes.Contains(buf[:n], []byte("netns-echo")) {
		t.Fatalf("got %q", buf[:n])
	}
	cancel()
}
