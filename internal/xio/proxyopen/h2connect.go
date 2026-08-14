package proxyopen

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/tlsopen"
)

func dialH2CONNECT(ctx context.Context, s parse.Spec, g *xio.Global, t proxyTarget) (net.Conn, error) {
	h2c := s.BoolOption("h2c")
	timeout := xio.ConnectTimeout(s)
	network := xio.ConnectNetworkForType(g, s, t.proxyHost, "tcp")
	dial := func(dctx context.Context, _, _ string) (net.Conn, error) {
		return xio.DialTCPAll(dctx, network, xio.StripBrackets(t.proxyHost), t.proxyPort, s, g, timeout, nil)
	}

	tr := &http.Transport{
		DialContext:       dial,
		ForceAttemptHTTP2: true,
		DisableKeepAlives: true,
	}
	var protos http.Protocols
	scheme := "https"
	if h2c {
		protos.SetHTTP1(false)
		protos.SetUnencryptedHTTP2(true)
		scheme = "http"
	} else {
		protos.SetHTTP1(false)
		protos.SetHTTP2(true)
		tlsCfg, err := tlsopen.TLSClientConfig(s, t.proxyHost)
		if err != nil {
			return nil, err
		}
		tlsCfg = tlsCfg.Clone()
		tlsCfg.NextProtos = []string{proxyALPN(s, "h2")}
		tr.TLSClientConfig = tlsCfg
	}
	tr.Protocols = &protos

	u := scheme + "://" + net.JoinHostPort(xio.StripBrackets(t.proxyHost), t.proxyPort) + "/"
	authority := net.JoinHostPort(t.connectHost, t.targetPort)

	var conn net.Conn
	err := xio.WithRetry(ctx, s, g, "PROXY-CONNECT", func() error {
		pr, pw := io.Pipe()
		req, e := http.NewRequestWithContext(ctx, http.MethodConnect, u, pr)
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
