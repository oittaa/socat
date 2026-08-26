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
		stopTimer()
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

// proxyHandshakeContext bounds RoundTrip until CONNECT succeeds. HTTP/2 and
// HTTP/3 abort the stream if the request context is cancelled, so the timer
// must be stopped on success without cancelling; cancel runs on Close.
func proxyHandshakeContext(parent context.Context, timeout time.Duration) (ctx context.Context, stopTimer, cancel context.CancelFunc) {
	if timeout <= 0 {
		return parent, func() {}, func() {}
	}
	ctx, cancel = context.WithCancel(parent)
	timer := time.AfterFunc(timeout, cancel)
	return ctx, func() { timer.Stop() }, cancel
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
