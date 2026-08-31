package wsopen

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

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

func TestUpgradeConnHandshakeTimeout(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	started := time.Now()
	if _, err := upgradeConn(server, "/", "", "", 30*time.Millisecond); err == nil {
		t.Fatal("incomplete WebSocket request did not time out")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("timeout took %s", elapsed)
	}
}

func TestWSConnectHandshakeTimeoutStalledPeer(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		time.Sleep(5 * time.Second)
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, err := parse.ParseSpec(fmt.Sprintf("WS:127.0.0.1:%d,handshake-timeout=0.2", port))
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = openWSConnect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err == nil {
		t.Fatal("stalled WebSocket peer did not time out")
	}
	elapsed := time.Since(started)
	if elapsed < 150*time.Millisecond {
		t.Fatalf("failed too quickly (%s); handshake-timeout may not have been applied: %v", elapsed, err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("handshake timeout took %s: %v", elapsed, err)
	}
}

func TestWSConnectHandshakeTimeoutDoesNotTruncateTCPConnect(t *testing.T) {
	hosts := []string{"192.0.2.1", "198.51.100.1", "203.0.113.1"}
	var lastElapsed time.Duration
	var lastErr error
	var lastHost string
	for _, host := range hosts {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s, err := parse.ParseSpec(fmt.Sprintf("WS:%s:1,connect-timeout=1,handshake-timeout=0.2", host))
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		started := time.Now()
		_, err = openWSConnect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
		elapsed := time.Since(started)
		cancel()
		lastElapsed, lastErr, lastHost = elapsed, err, host
		if elapsed < 700*time.Millisecond {
			t.Logf("%s completed in %s (likely RST); trying next TEST-NET address: %v", host, elapsed, err)
			continue
		}
		if err == nil {
			t.Fatalf("%s: expected connect failure against non-completing SYN, elapsed %s", host, elapsed)
		}
		if elapsed > 2500*time.Millisecond {
			t.Fatalf("%s: connect-timeout took %s: %v", host, elapsed, err)
		}
		return
	}
	t.Fatalf("no TEST-NET address blackholed SYN (last %s elapsed %s: %v); handshake-timeout must not be tested against an immediate RST", lastHost, lastElapsed, lastErr)
}

func echoWSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer func() { _ = c.CloseNow() }()
		nc := websocket.NetConn(r.Context(), c, websocket.MessageBinary)
		defer func() { _ = nc.Close() }()
		_, _ = io.Copy(nc, nc)
	})
}

func TestWSClientHTTPtest(t *testing.T) {
	srv := httptest.NewServer(echoWSHandler())
	defer srv.Close()
	u := strings.TrimPrefix(srv.URL, "http://")
	host, port, err := net.SplitHostPort(u)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := parse.ParseSpec(fmt.Sprintf("WS:%s:%s", host, port))
	if err != nil {
		t.Fatal(err)
	}
	g := &xio.Global{Log: logx.New()}
	o, err := openWSConnect(ctx, s, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	payload := []byte("hello-ws")
	if _, err := o.Stream.Write(payload); err != nil {
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

func TestWSSClientHTTPtest(t *testing.T) {
	srv := httptest.NewTLSServer(echoWSHandler())
	defer srv.Close()
	u := strings.TrimPrefix(srv.URL, "https://")
	host, port, err := net.SplitHostPort(u)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := parse.ParseSpec(fmt.Sprintf("WSS:%s:%s,verify=0", host, port))
	if err != nil {
		t.Fatal(err)
	}
	g := &xio.Global{Log: logx.New()}
	o, err := openWSSConnect(ctx, s, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	payload := []byte("hello-wss")
	if _, err := o.Stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(o.Stream, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q", got)
	}
	if g.TLSVars["PROTO_VERSION"] == "" {
		t.Fatal("WSS client did not record the negotiated TLS version")
	}
	if g.TLSVars["CIPHER"] == "" {
		t.Fatal("WSS client did not record the negotiated cipher")
	}
	if g.TLSVars["X509_SUBJECT"] == "" {
		t.Fatal("WSS client did not record the peer certificate subject")
	}
}

func TestWSNetConnAbortOnTimeoutClosesRaw(t *testing.T) {
	raw, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	c := &wsNetConn{raw: raw}
	c.abortOnTimeout(os.ErrDeadlineExceeded)
	_ = peer.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	var b [1]byte
	if _, err := peer.Read(b[:]); err == nil {
		t.Fatal("timeout abort did not close the raw connection")
	}
}

func TestWSNetConnAbortOnTimeoutIgnoresOtherErrors(t *testing.T) {
	raw, peer := net.Pipe()
	defer func() { _ = raw.Close() }()
	defer func() { _ = peer.Close() }()
	c := &wsNetConn{raw: raw}
	c.abortOnTimeout(io.EOF)
	done := make(chan struct{})
	go func() {
		var b [1]byte
		_, _ = peer.Read(b[:])
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("non-timeout error closed the raw connection")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestWSSClientVerifyCA(t *testing.T) {
	srv := httptest.NewTLSServer(echoWSHandler())
	defer srv.Close()
	u := strings.TrimPrefix(srv.URL, "https://")
	host, port, err := net.SplitHostPort(u)
	if err != nil {
		t.Fatal(err)
	}
	// Server uses httptest cert; without skip verify the client must fail unless we inject roots.
	// verify=1 against public roots should fail (unknown CA).
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, err := parse.ParseSpec(fmt.Sprintf("WSS:%s:%s,verify=1", host, port))
	if err != nil {
		t.Fatal(err)
	}
	_, err = openWSSConnect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err == nil {
		t.Fatal("expected verify failure against httptest cert")
	}
}

func startListenPIPE(t *testing.T, ctx context.Context, spec string) *xio.Opened {
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
	lo, err := xio.OpenChannel(ctx, ls, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	if lo.Listener == nil {
		_ = lo.Close()
		t.Fatal("listen address did not return a listener (use fork)")
	}
	t.Cleanup(func() { _ = lo.Close() })
	go func() { _ = xio.RunOpened(ctx, lo, pipe, g) }()
	return lo
}

func wsListenPort(t *testing.T, o *xio.Opened) int {
	t.Helper()
	ta, ok := o.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("WS-LISTEN addr %T", o.Listener.Addr())
	}
	if ta.Port == 0 {
		t.Fatal("WS-LISTEN bound port 0")
	}
	return ta.Port
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

func TestWSListenConnectEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	port := wsListenPort(t, startListenPIPE(t, ctx, "WS-LISTEN:0,reuseaddr,bind=127.0.0.1,fork"))

	cs, err := parse.ParseSpec(fmt.Sprintf("WS:127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openWSConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	echoRoundtrip(t, o.Stream, []byte("roundtrip"))
}

func TestWSListenPathMismatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	port := wsListenPort(t, startListenPIPE(t, ctx, "WS-LISTEN:0/echo,reuseaddr,bind=127.0.0.1,fork"))

	cs, err := parse.ParseSpec(fmt.Sprintf("WS:127.0.0.1:%d/other", port))
	if err != nil {
		t.Fatal(err)
	}
	_, err = openWSConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err == nil {
		t.Fatal("expected path mismatch error")
	}

	ok, err := parse.ParseSpec(fmt.Sprintf("WS:127.0.0.1:%d/echo", port))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openWSConnect(ctx, ok, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	echoRoundtrip(t, o.Stream, []byte("ok"))
}

func TestWSListenPathOption(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	port := wsListenPort(t, startListenPIPE(t, ctx, "WS-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,path=/ws"))

	ok, err := parse.ParseSpec(fmt.Sprintf("WS:127.0.0.1:%d,path=/ws", port))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openWSConnect(ctx, ok, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	echoRoundtrip(t, o.Stream, []byte("pathopt"))
}

func TestWSListenForkTwoClients(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	port := wsListenPort(t, startListenPIPE(t, ctx, "WS-LISTEN:0,reuseaddr,bind=127.0.0.1,fork"))

	for i, msg := range []string{"one", "two"} {
		cs, err := parse.ParseSpec(fmt.Sprintf("WS:127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		o, err := openWSConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		echoRoundtrip(t, o.Stream, []byte(msg))
		_ = o.Close()
	}
}

func TestWSSListenConnectEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	port := wsListenPort(t, startListenPIPE(t, ctx, fmt.Sprintf("WSS-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s", listenCert(t))))

	cs, err := parse.ParseSpec(fmt.Sprintf("WSS:127.0.0.1:%d,verify=0", port))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openWSSConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	echoRoundtrip(t, o.Stream, []byte("hello-wss-listen"))
}

func TestWSListenOriginReject(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	port := wsListenPort(t, startListenPIPE(t, ctx, "WS-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,origin=example.com"))

	bad, err := parse.ParseSpec(fmt.Sprintf("WS:127.0.0.1:%d,origin=http://evil.com", port))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openWSConnect(ctx, bad, xio.ModeRDWR, &xio.Global{Log: logx.New()}); err == nil {
		t.Fatal("expected origin rejection")
	}

	ok, err := parse.ParseSpec(fmt.Sprintf("WS:127.0.0.1:%d,origin=http://example.com", port))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openWSConnect(ctx, ok, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	echoRoundtrip(t, o.Stream, []byte("origin-ok"))
}

func TestWSListenProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	port := wsListenPort(t, startListenPIPE(t, ctx, "WS-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,protocol=chat"))

	cs, err := parse.ParseSpec(fmt.Sprintf("WS:127.0.0.1:%d,protocol=chat", port))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openWSConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	echoRoundtrip(t, o.Stream, []byte("proto"))
}
