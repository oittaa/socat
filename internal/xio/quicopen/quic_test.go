package quicopen

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testcert"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/fileopen"
)

func listenCert(t *testing.T) string {
	t.Helper()
	p, err := testcert.WriteTempListenCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func startListenPIPE(t *testing.T, ctx context.Context, spec string) int {
	t.Helper()
	ls, err := parse.ParseChannel(spec)
	if err != nil {
		t.Fatal(err)
	}
	pipe, err := parse.ParseChannel("PIPE")
	if err != nil {
		t.Fatal(err)
	}
	g := xio.NewSession(xio.Options{Linger: 200 * time.Millisecond}, logx.New())
	// Bind here so the OS allocates a free UDP port without races.
	lo, err := xio.OpenChannel(ctx, ls, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	port := lo.Listener().Addr().(*net.UDPAddr).Port
	go func() { _ = xio.RunOpened(ctx, lo, pipe, g) }()
	return port
}

func echoRoundtrip(t *testing.T, st io.ReadWriter, payload []byte) {
	t.Helper()
	if _, err := st.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(st, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q", got)
	}
}

func TestQUICListenConnectEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	port := startListenPIPE(t, ctx, fmt.Sprintf("QUIC-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s", listenCert(t)))

	cs, err := parse.ParseSpec(fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0", port))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openQUICConnect(ctx, mustAddr(t, cs), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	echoRoundtrip(t, o.Stream(), []byte("quic-roundtrip"))
}

func TestQUICVerifyFailsWithoutTrust(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	port := startListenPIPE(t, ctx, fmt.Sprintf("QUIC-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s", listenCert(t)))

	cs, err := parse.ParseSpec(fmt.Sprintf("QUIC:127.0.0.1:%d,verify=1", port))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openQUICConnect(ctx, mustAddr(t, cs), xio.ModeRDWR, &xio.Global{Log: logx.New()}); err == nil {
		t.Fatal("expected verify failure against untrusted server cert")
	}
}

func TestQUICALPNMismatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	port := startListenPIPE(t, ctx, fmt.Sprintf("QUIC-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,alpn=socat,cert=%s", listenCert(t)))

	cs, err := parse.ParseSpec(fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0,alpn=other", port))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openQUICConnect(ctx, mustAddr(t, cs), xio.ModeRDWR, &xio.Global{Log: logx.New()}); err == nil {
		t.Fatal("expected ALPN mismatch")
	}
}

func TestQUICListenForkTwoClients(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	port := startListenPIPE(t, ctx, fmt.Sprintf("QUIC-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s", listenCert(t)))

	for i, msg := range []string{"one", "two"} {
		cs, err := parse.ParseSpec(fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0", port))
		if err != nil {
			t.Fatal(err)
		}
		o, err := openQUICConnect(ctx, mustAddr(t, cs), xio.ModeRDWR, &xio.Global{Log: logx.New()})
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		echoRoundtrip(t, o.Stream(), []byte(msg))
		_ = o.Close()
	}
}

func TestQUICConnectLowportBindFamilyMismatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cs, err := parse.ParseSpec("QUIC:127.0.0.1:9,pf=ip4,bind=::,lowport,verify=0")
	if err != nil {
		t.Fatal(err)
	}
	_, err = openQUICConnect(ctx, mustAddr(t, cs), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err == nil || !strings.Contains(err.Error(), "address family mismatch") {
		t.Fatalf("want bind family mismatch, got %v", err)
	}
}
