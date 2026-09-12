package xio_test

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

// startListenPIPE starts listenSpec paired with PIPE and returns after the
// listener is bound. Non-fork UDP-LISTEN OpenChannel waits for the first
// datagram, so waiting on OpenChannel deadlocks: the client cannot send until
// this helper returns.
func startListenPIPE(t *testing.T, ctx context.Context, g *xio.Global, spec string) {
	t.Helper()
	ls, err := parse.ParseChannel(spec)
	if err != nil {
		t.Fatal(err)
	}
	if ls.Single == nil {
		t.Fatalf("listen spec: %s", spec)
	}
	pipe, err := parse.ParseChannel("PIPE")
	if err != nil {
		t.Fatal(err)
	}
	wantHost := ""
	for _, o := range ls.Single.Options {
		if o.Name == "bind" {
			wantHost = o.Value
		}
	}
	wantPort := 0
	if len(ls.Single.Params) > 0 {
		wantPort, _ = strconv.Atoi(ls.Single.Params[0])
	}
	bound := make(chan net.Addr, 1)
	restore := xio.SetListenBoundTestHook(func(addr net.Addr) {
		if !listenAddrMatches(addr, wantHost, wantPort) {
			return
		}
		select {
		case bound <- addr:
		default:
		}
	})
	t.Cleanup(restore)
	openErr := make(chan error, 1)
	go func() {
		lo, err := xio.OpenChannel(ctx, ls, xio.ModeRDWR, g)
		if err != nil {
			openErr <- err
			return
		}
		_ = xio.RunOpened(ctx, lo, pipe, g)
	}()
	select {
	case <-bound:
	case err := <-openErr:
		t.Fatalf("listen %s: %v", spec, err)
	case <-ctx.Done():
		t.Fatalf("listen %s: %v", spec, ctx.Err())
	case <-time.After(5 * time.Second):
		t.Fatalf("listen %s: timed out waiting for bind", spec)
	}
}

func listenAddrMatches(addr net.Addr, host string, port int) bool {
	var ip net.IP
	var gotPort int
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip, gotPort = a.IP, a.Port
	case *net.UDPAddr:
		ip, gotPort = a.IP, a.Port
	default:
		h, p, err := net.SplitHostPort(addr.String())
		if err != nil {
			return false
		}
		ip = net.ParseIP(h)
		gotPort, err = strconv.Atoi(p)
		if err != nil {
			return false
		}
	}
	if port != 0 && gotPort != port {
		return false
	}
	if host == "" {
		return true
	}
	want := net.ParseIP(host)
	return want != nil && ip.Equal(want)
}

// TestStartListenPIPEReturnsBeforeUDPDatagram proves listen readiness is the
// bind notification, not OpenChannel. Non-fork UDP4-LISTEN OpenChannel waits
// for the first datagram; waiting on it here times out because nothing sends.
func TestStartListenPIPEReturnsBeforeUDPDatagram(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	g := &xio.Global{Log: logx.New(), BlockSize: 8192, Linger: 200 * time.Millisecond}
	startListenPIPE(t, ctx, g, "UDP4-LISTEN:0,reuseaddr,bind=127.0.0.1")
}
