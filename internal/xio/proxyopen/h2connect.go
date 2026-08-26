package proxyopen

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/tlsopen"
)

func dialH2CONNECT(ctx context.Context, s parse.Spec, g *xio.Global, t proxyTarget) (net.Conn, error) {
	h2c := s.BoolOption("h2c")
	connectTimeout := xio.ConnectTimeout(s)
	handshakeTimeout := xio.HandshakeTimeout(s)
	network := xio.ConnectNetworkForType(g, s, t.proxyHost, "tcp")

	var tlsCfg *tls.Config
	scheme := "https"
	if h2c {
		scheme = "http"
	} else {
		cfg, err := tlsopen.TLSClientConfig(s, t.proxyHost)
		if err != nil {
			return nil, err
		}
		tlsCfg = cfg.Clone()
		tlsCfg.NextProtos = []string{proxyALPN(s, "h2")}
	}

	u := scheme + "://" + net.JoinHostPort(xio.StripBrackets(t.proxyHost), t.proxyPort) + "/"
	authority := net.JoinHostPort(t.connectHost, t.targetPort)

	var conn net.Conn
	err := xio.WithRetry(ctx, s, g, "PROXY-CONNECT", func() error {
		raw, e := xio.DialTCPAll(ctx, network, xio.StripBrackets(t.proxyHost), t.proxyPort, s, g, connectTimeout, nil)
		if e != nil {
			return e
		}
		if handshakeTimeout > 0 {
			if e := raw.SetDeadline(time.Now().Add(handshakeTimeout)); e != nil {
				logx.CloseQuiet(raw)
				return e
			}
		}

		hctx, stopTimer, cancelHandshake := proxyHandshakeContext(ctx, handshakeTimeout)
		success := false
		defer func() {
			if !success {
				stopTimer()
				cancelHandshake()
				logx.CloseQuiet(raw)
			}
		}()

		take := alreadyDialed(raw)
		tr := &http.Transport{
			DialContext:       take,
			ForceAttemptHTTP2: true,
			DisableKeepAlives: true,
		}
		var protos http.Protocols
		if h2c {
			protos.SetHTTP1(false)
			protos.SetUnencryptedHTTP2(true)
		} else {
			protos.SetHTTP1(false)
			protos.SetHTTP2(true)
			attemptTLS := tlsCfg.Clone()
			tr.TLSClientConfig = attemptTLS
			tr.DialTLSContext = func(dctx context.Context, _, _ string) (net.Conn, error) {
				c, e := take(dctx, "", "")
				if e != nil {
					return nil, e
				}
				tc := tls.Client(c, attemptTLS.Clone())
				if e := tc.HandshakeContext(dctx); e != nil {
					logx.CloseQuiet(c)
					return nil, e
				}
				return tc, nil
			}
		}
		tr.Protocols = &protos

		pr, pw := io.Pipe()
		req, e := http.NewRequestWithContext(hctx, http.MethodConnect, u, pr)
		if e != nil {
			_ = pw.Close()
			return e
		}
		req.Host = authority
		req.ContentLength = -1
		if auth, e := proxyAuthString(s); e != nil {
			_ = pw.Close()
			return e
		} else if auth != "" {
			req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
		}
		resp, e := tr.RoundTrip(req)
		if e != nil {
			_ = pw.Close()
			tr.CloseIdleConnections()
			return e
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			_ = pw.Close()
			_ = resp.Body.Close()
			tr.CloseIdleConnections()
			return fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
		}
		if e := finishCONNECTHandshake(hctx, stopTimer, pw, resp); e != nil {
			tr.CloseIdleConnections()
			return e
		}
		_ = raw.SetDeadline(time.Time{})
		success = true
		conn = &pipeConn{
			r:      resp.Body,
			w:      pw,
			local:  staticAddr("h2", u),
			remote: staticAddr("h2", authority),
			extra: []io.Closer{closerFunc(func() error {
				cancelHandshake()
				tr.CloseIdleConnections()
				return nil
			})},
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return conn, nil
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

// proxyHandshakeContext bounds RoundTrip until CONNECT succeeds. HTTP/2 and
// HTTP/3 abort the stream if the request context is cancelled, so success
// stops the timer without cancelling; cancel runs on Close. Timer.Stop does
// not wait for an already-running AfterFunc; completed serializes that
// callback with stop so a late fire cannot cancel after stop returns.
// handshake-timeout is a Go extra (classic tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba and official master
// af5388c898c7bb60997935aee93c223deba60c4a have no equivalent).
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

func alreadyDialed(c net.Conn) func(context.Context, string, string) (net.Conn, error) {
	var mu sync.Mutex
	return func(context.Context, string, string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		if c == nil {
			return nil, fmt.Errorf("proxy TCP connection already used")
		}
		out := c
		c = nil
		return out, nil
	}
}
