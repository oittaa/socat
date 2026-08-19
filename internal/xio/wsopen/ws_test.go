package wsopen

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
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

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func startListenPIPE(t *testing.T, ctx context.Context, spec string) {
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
	// Bind here so a readiness probe cannot steal the TCP port (macOS CI flake).
	lo, err := xio.OpenChannel(ctx, ls, xio.ModeRDWR, g)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = xio.RunOpened(ctx, lo, pipe, g) }()
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
	port := freeTCPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	startListenPIPE(t, ctx, fmt.Sprintf("WS-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork", port))

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
	port := freeTCPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	startListenPIPE(t, ctx, fmt.Sprintf("WS-LISTEN:%d/echo,reuseaddr,bind=127.0.0.1,fork", port))

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
	port := freeTCPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	startListenPIPE(t, ctx, fmt.Sprintf("WS-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,path=/ws", port))

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
	port := freeTCPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	startListenPIPE(t, ctx, fmt.Sprintf("WS-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork", port))

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
	port := freeTCPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	startListenPIPE(t, ctx, fmt.Sprintf("WSS-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s", port, listenCert(t)))

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
	port := freeTCPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	startListenPIPE(t, ctx, fmt.Sprintf("WS-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,origin=example.com", port))

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
	port := freeTCPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	startListenPIPE(t, ctx, fmt.Sprintf("WS-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,protocol=chat", port))

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
