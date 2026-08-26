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

		hctx := ctx
		var cancel context.CancelFunc
		if handshakeTimeout > 0 {
			hctx, cancel = context.WithTimeout(ctx, handshakeTimeout)
			defer cancel()
		}

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
			logx.CloseQuiet(raw)
			return e
		}
		req.Host = authority
		req.ContentLength = -1
		if auth, e := proxyAuthString(s); e != nil {
			_ = pw.Close()
			logx.CloseQuiet(raw)
			return e
		} else if auth != "" {
			req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
		}
		resp, e := tr.RoundTrip(req)
		if e != nil {
			_ = pw.Close()
			tr.CloseIdleConnections()
			logx.CloseQuiet(raw)
			return e
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			_ = pw.Close()
			_ = resp.Body.Close()
			tr.CloseIdleConnections()
			logx.CloseQuiet(raw)
			return fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
		}
		_ = raw.SetDeadline(time.Time{})
		conn = &pipeConn{
			r:      resp.Body,
			w:      pw,
			local:  staticAddr("h2", u),
			remote: staticAddr("h2", authority),
			extra:  []io.Closer{closerFunc(func() error { tr.CloseIdleConnections(); return nil })},
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return conn, nil
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
