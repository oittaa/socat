package wsopen

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
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
	o, err := openWSConnect(ctx, mustAddr(t, cs), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	echoRoundtrip(t, o.Stream, []byte("roundtrip"))
}

func TestWSListenPathOption(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	port := wsListenPort(t, startListenPIPE(t, ctx, "WS-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,path=/ws"))

	ok, err := parse.ParseSpec(fmt.Sprintf("WS:127.0.0.1:%d,path=/ws", port))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openWSConnect(ctx, mustAddr(t, ok), xio.ModeRDWR, &xio.Global{Log: logx.New()})
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
		o, err := openWSConnect(ctx, mustAddr(t, cs), xio.ModeRDWR, &xio.Global{Log: logx.New()})
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
	o, err := openWSSConnect(ctx, mustAddr(t, cs), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	echoRoundtrip(t, o.Stream, []byte("hello-wss-listen"))
}

func TestWSListenProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	port := wsListenPort(t, startListenPIPE(t, ctx, "WS-LISTEN:0,reuseaddr,bind=127.0.0.1,fork,protocol=chat"))

	cs, err := parse.ParseSpec(fmt.Sprintf("WS:127.0.0.1:%d,protocol=chat", port))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openWSConnect(ctx, mustAddr(t, cs), xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	echoRoundtrip(t, o.Stream, []byte("proto"))
}
