package proxyopen

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/tlsopen"
)

func dialH3CONNECT(ctx context.Context, s parse.Spec, g *xio.Global, t proxyTarget) (net.Conn, error) {
	tlsCfg, err := tlsopen.TLSClientConfig(s, t.proxyHost)
	if err != nil {
		return nil, err
	}
	tlsCfg = tlsCfg.Clone()
	if tlsCfg.MinVersion < tls.VersionTLS13 {
		tlsCfg.MinVersion = tls.VersionTLS13
	}
	tlsCfg.NextProtos = []string{proxyALPN(s, http3.NextProtoH3)}

	u := "https://" + net.JoinHostPort(xio.StripBrackets(t.proxyHost), t.proxyPort) + "/"
	authority := net.JoinHostPort(t.connectHost, t.targetPort)
	attemptTimeout := xio.CombinedConnectHandshakeTimeout(s)
	idle := xio.QUICHandshakeIdleTimeout(s)

	var conn net.Conn
	err = xio.WithRetry(ctx, s, g, "PROXY-CONNECT", func() error {
		tr := &http3.Transport{
			TLSClientConfig: tlsCfg.Clone(),
			QUICConfig:      &quic.Config{HandshakeIdleTimeout: idle},
		}
		cctx, stopTimer, cancelHandshake := proxyHandshakeContext(ctx, attemptTimeout)
		success := false
		defer func() {
			if !success {
				stopTimer()
				cancelHandshake()
				_ = tr.Close()
			}
		}()
		pr, pw := io.Pipe()
		req, e := http.NewRequestWithContext(cctx, http.MethodConnect, u, pr)
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
			return e
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			_ = pw.Close()
			_ = resp.Body.Close()
			return fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
		}
		if e := finishCONNECTHandshake(cctx, stopTimer, pw, resp); e != nil {
			return e
		}
		success = true
		conn = &pipeConn{
			r:      resp.Body,
			w:      pw,
			local:  staticAddr("h3", u),
			remote: staticAddr("h3", authority),
			extra: []io.Closer{closerFunc(func() error {
				cancelHandshake()
				return tr.Close()
			})},
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return conn, nil
}
