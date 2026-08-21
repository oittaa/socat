package quicopen

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/testcert"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/fileopen"
	"github.com/oittaa/socat/internal/xio/tlsopen"
)

func listenCert(t *testing.T) string {
	t.Helper()
	p, err := tlsopen.WriteTempListenCert(t.TempDir())
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
	g := &xio.Global{Log: logx.New(), Linger: 200 * time.Millisecond}
	// Bind here so the OS allocates a free UDP port without races.
	lo, err := xio.OpenChannel(ctx, ls, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	port := lo.Listener.Addr().(*net.UDPAddr).Port
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
	o, err := openQUICConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	echoRoundtrip(t, o.Stream, []byte("quic-roundtrip"))
}

func TestQUICVerifyFailsWithoutTrust(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	port := startListenPIPE(t, ctx, fmt.Sprintf("QUIC-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s", listenCert(t)))

	cs, err := parse.ParseSpec(fmt.Sprintf("QUIC:127.0.0.1:%d,verify=1", port))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openQUICConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()}); err == nil {
		t.Fatal("expected verify failure against untrusted server cert")
	}
}

func TestQUICVerifySucceedsWithTrustedCerts(t *testing.T) {
	certs := writeTrustCerts(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	port := startListenPIPE(t, ctx, fmt.Sprintf(
		"QUIC-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=1,cert=%s,key=%s,cafile=%s",
		certs.serverCert, certs.serverKey, certs.caFile,
	))

	cs, err := parse.ParseSpec(fmt.Sprintf(
		"QUIC:127.0.0.1:%d,verify=1,cert=%s,key=%s,cafile=%s,commonname=localhost",
		port, certs.clientCert, certs.clientKey, certs.caFile,
	))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openQUICConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	echoRoundtrip(t, o.Stream, []byte("quic-verify-ok"))
}

func TestQUICALPNMismatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	port := startListenPIPE(t, ctx, fmt.Sprintf("QUIC-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,alpn=socat,cert=%s", listenCert(t)))

	cs, err := parse.ParseSpec(fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0,alpn=other", port))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openQUICConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()}); err == nil {
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
		o, err := openQUICConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		echoRoundtrip(t, o.Stream, []byte(msg))
		_ = o.Close()
	}
}

func TestQUICHalfClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	port := startListenPIPE(t, ctx, fmt.Sprintf("QUIC-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s", listenCert(t)))

	cs, err := parse.ParseSpec(fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0", port))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openQUICConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	payload := []byte("half-close")
	if _, err := o.Stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := o.Stream.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(o.Stream, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q", got)
	}
}

func TestQUICReadOnlyClientReceivesListenText(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	payload := "quic-one-way"
	ls, err := parse.ParseChannel(fmt.Sprintf(
		"QUIC-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s", listenCert(t),
	))
	if err != nil {
		t.Fatal(err)
	}
	text, err := parse.ParseChannel("TEXT:" + payload)
	if err != nil {
		t.Fatal(err)
	}
	g := &xio.Global{Log: logx.New(), Linger: 200 * time.Millisecond, RightToLeft: true}
	lo, err := xio.OpenChannel(ctx, ls, xio.ModeWrite, g)
	if err != nil {
		t.Fatal(err)
	}
	port := lo.Listener.Addr().(*net.UDPAddr).Port
	go func() { _ = xio.RunOpened(ctx, lo, text, g) }()

	cs, err := parse.ParseSpec(fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0", port))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openQUICConnect(ctx, cs, xio.ModeRead, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(o.Stream, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("got %q", got)
	}
}

type trustCerts struct {
	caFile, serverCert, serverKey, clientCert, clientKey string
}

func writeTrustCerts(t *testing.T) trustCerts {
	t.Helper()
	dir := t.TempDir()
	a, err := testcert.NewAuthority("socat-test-ca")
	if err != nil {
		t.Fatal(err)
	}
	writeFile := func(name string, data []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	srv, err := a.Leaf("localhost", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		[]net.IP{net.ParseIP("127.0.0.1")}, []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	cli, err := a.Leaf("client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, serverKey, err := srv.WriteCertAndKey(dir, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	clientCert, clientKey, err := cli.WriteCertAndKey(dir, "client")
	if err != nil {
		t.Fatal(err)
	}
	return trustCerts{
		caFile:     writeFile("ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.DER})),
		serverCert: serverCert,
		serverKey:  serverKey,
		clientCert: clientCert,
		clientKey:  clientKey,
	}
}

func quicNetConnOf(t *testing.T, o *xio.Opened) *quicNetConn {
	t.Helper()
	ns, ok := o.Stream.(relay.NetStream)
	if !ok {
		t.Fatalf("stream is %T, want relay.NetStream", o.Stream)
	}
	qnc, ok := ns.Conn.(*quicNetConn)
	if !ok {
		t.Fatalf("conn is %T, want *quicNetConn", ns.Conn)
	}
	return qnc
}

func TestQUICCloseWithoutWritesClosesPromptly(t *testing.T) {
	// Connect-and-close without any payload or FIN has nothing in flight;
	// CONNECTION_CLOSE must not wait out the drain period.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	port := startListenPIPE(t, ctx, fmt.Sprintf("QUIC-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s", listenCert(t)))

	cs, err := parse.ParseSpec(fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0", port))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openQUICConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	qnc := quicNetConnOf(t, o)
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-qnc.qc.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("write-free connection was not closed promptly")
	}
}

func TestQUICDataConnectionDrainsBeforeClose(t *testing.T) {
	// A connection that carried payload keeps the drain delay so the final
	// STREAM bytes survive CONNECTION_CLOSE.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	port := startListenPIPE(t, ctx, fmt.Sprintf("QUIC-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s", listenCert(t)))

	cs, err := parse.ParseSpec(fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0", port))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openQUICConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	qnc := quicNetConnOf(t, o)
	echoRoundtrip(t, o.Stream, []byte("drain-me"))
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-qnc.qc.Context().Done():
		t.Fatal("data-carrying connection closed before the drain elapsed")
	case <-time.After(2 * time.Second):
	}
	select {
	case <-qnc.qc.Context().Done():
	case <-time.After(6 * time.Second):
		t.Fatal("data-carrying connection was never closed")
	}
}
