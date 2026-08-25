package tlsopen

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testcert"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/fileopen"
)

func TestTLSListenConnectEchoUseCase(t *testing.T) {
	cert, err := testcert.WriteTempListenCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	g := &xio.Global{BlockSize: 8192, Log: logx.New(), Linger: 200 * time.Millisecond}
	ls, err := parse.ParseChannel("TLS-LISTEN:0,reuseaddr,fork,bind=127.0.0.1,verify=0,cert=" + cert)
	if err != nil {
		t.Fatal(err)
	}
	lo, err := xio.OpenChannel(ctx, ls, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	if lo.Listener == nil {
		_ = lo.Close()
		t.Fatal("TLS-LISTEN did not return a listener")
	}
	pipe, err := parse.ParseChannel("PIPE")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = xio.RunOpened(ctx, lo, pipe, g) }()
	port := lo.Listener.Addr().(*net.TCPAddr).Port
	cs, err := parse.ParseChannel("TLS:127.0.0.1:" + strconv.Itoa(port) + ",verify=0,connect-timeout=2")
	if err != nil {
		t.Fatal(err)
	}
	cli, err := xio.OpenChannel(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	const payload = "tls-use"
	if _, err := io.WriteString(cli.Stream, payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(cli.Stream, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("got %q", got)
	}
}

func TestTLSConnectAndListenAliases(t *testing.T) {
	cert, err := testcert.WriteTempListenCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	g := &xio.Global{BlockSize: 8192, Log: logx.New(), Linger: 200 * time.Millisecond}
	ls, err := parse.ParseChannel("TLS-L:0,reuseaddr,fork,bind=127.0.0.1,verify=0,cert=" + cert)
	if err != nil {
		t.Fatal(err)
	}
	lo, err := xio.OpenChannel(ctx, ls, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	if lo.Listener == nil {
		_ = lo.Close()
		t.Fatal("TLS-L did not return a listener")
	}
	pipe, err := parse.ParseChannel("PIPE")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = xio.RunOpened(ctx, lo, pipe, g) }()
	port := lo.Listener.Addr().(*net.TCPAddr).Port
	cs, err := parse.ParseChannel("TLS-CONNECT:127.0.0.1:" + strconv.Itoa(port) + ",verify=0,connect-timeout=2")
	if err != nil {
		t.Fatal(err)
	}
	cli, err := xio.OpenChannel(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	const payload = "tls-alias"
	if _, err := io.WriteString(cli.Stream, payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(cli.Stream, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("got %q", got)
	}
}
