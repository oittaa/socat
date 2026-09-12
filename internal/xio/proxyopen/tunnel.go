package proxyopen

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
)

// pipeConn is a net.Conn over a CONNECT stream: write to the request body,
// read from the response body.
type pipeConn struct {
	r      io.ReadCloser
	w      io.WriteCloser
	local  net.Addr
	remote net.Addr
	extra  []io.Closer
}

func (c *pipeConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *pipeConn) Write(p []byte) (int, error) { return c.w.Write(p) }

func (c *pipeConn) CloseWrite() error { return c.w.Close() }

func (c *pipeConn) Close() error {
	_ = c.w.Close()
	_ = c.r.Close()
	for _, x := range c.extra {
		_ = x.Close()
	}
	return nil
}

func (c *pipeConn) LocalAddr() net.Addr  { return c.local }
func (c *pipeConn) RemoteAddr() net.Addr { return c.remote }

func (c *pipeConn) SetDeadline(time.Time) error      { return nil }
func (c *pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pipeConn) SetWriteDeadline(time.Time) error { return nil }

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

func staticAddr(network, s string) net.Addr { return &strAddr{net: network, s: s} }

type strAddr struct{ net, s string }

func (a *strAddr) Network() string { return a.net }
func (a *strAddr) String() string  { return a.s }

// connectTunnel is the HTTP CONNECT request shared by HTTP/2 and HTTP/3.
// Transports stay in the dialers; this owns pipes, auth, 2xx, and cleanup.
type connectTunnel struct {
	roundTrip http.RoundTripper
	handshake context.Context
	stopTimer func()
	proxy     addrconfig.Proxy
	url       string
	authority string
	network   string
	closers   []io.Closer
}

func openCONNECTTunnel(t connectTunnel) (net.Conn, error) {
	if t.stopTimer == nil {
		t.stopTimer = func() {}
	}
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(t.handshake, http.MethodConnect, t.url, pr)
	if err != nil {
		_ = pw.Close()
		return nil, err
	}
	req.Host = t.authority
	req.ContentLength = -1
	auth, err := proxyAuthString(t.proxy)
	if err != nil {
		_ = pw.Close()
		return nil, err
	}
	if auth != "" {
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	}
	resp, err := t.roundTrip.RoundTrip(req)
	if err != nil {
		_ = pw.Close()
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_ = pw.Close()
		_ = resp.Body.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}
	if err := finishCONNECTHandshake(t.handshake, t.stopTimer, pw, resp); err != nil {
		return nil, err
	}
	return &pipeConn{
		r:      resp.Body,
		w:      pw,
		local:  staticAddr(t.network, t.url),
		remote: staticAddr(t.network, t.authority),
		extra:  t.closers,
	}, nil
}

// handshakeTimerHook, if set, is invoked when a handshake timer is armed.
// stop marks completion; fire is the AfterFunc body. A non-nil return
// replaces the success-side stop function (it must still invoke stop).
// Tests use this to race completion with the timeout callback without
// depending on wall-clock timing.
var (
	handshakeTimerHookMu sync.Mutex
	handshakeTimerHook   func(stop, fire func()) (wrap func())
)

func setHandshakeTimerHook(hook func(stop, fire func()) (wrap func())) {
	handshakeTimerHookMu.Lock()
	handshakeTimerHook = hook
	handshakeTimerHookMu.Unlock()
}

func handshakeTimerHookSnapshot() func(stop, fire func()) (wrap func()) {
	handshakeTimerHookMu.Lock()
	defer handshakeTimerHookMu.Unlock()
	return handshakeTimerHook
}

// finishCONNECTHandshake stops the handshake timer without cancelling the
// request context. HTTP/2 and HTTP/3 abort CONNECT if that context is
// cancelled, so success must not cancel. If the timeout callback already
// won, close the CONNECT body instead of returning a live tunnel.
func finishCONNECTHandshake(ctx context.Context, stopTimer func(), pw *io.PipeWriter, resp *http.Response) error {
	stopTimer()
	if err := ctx.Err(); err != nil {
		_ = pw.Close()
		_ = resp.Body.Close()
		return err
	}
	return nil
}

// proxyHandshakeContext bounds RoundTrip until CONNECT succeeds. Success
// stops the timer without cancelling (HTTP/2/3 abort CONNECT if cancelled).
// completed serializes AfterFunc with stop so a late fire cannot cancel after stop.
// handshake-timeout has no C equivalent.
func proxyHandshakeContext(parent context.Context, timeout time.Duration) (ctx context.Context, stopTimer, cancel context.CancelFunc) {
	if timeout <= 0 {
		return parent, func() {}, func() {}
	}
	ctx, cancel = context.WithCancel(parent)
	var mu sync.Mutex
	var completed bool
	fire := func() {
		mu.Lock()
		defer mu.Unlock()
		if completed {
			return
		}
		cancel()
	}
	timer := time.AfterFunc(timeout, fire)
	stopTimer = func() {
		mu.Lock()
		defer mu.Unlock()
		completed = true
		timer.Stop()
	}
	if hook := handshakeTimerHookSnapshot(); hook != nil {
		if wrap := hook(stopTimer, fire); wrap != nil {
			stopTimer = wrap
		}
	}
	return ctx, stopTimer, cancel
}
