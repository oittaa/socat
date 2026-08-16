package wsopen

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"

	"github.com/coder/websocket"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/tlsopen"
)

func openWSConnect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openWSConnectScheme(ctx, s, mode, g, "ws")
}

func openWSSConnect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openWSConnectScheme(ctx, s, mode, g, "wss")
}

func openWSConnectScheme(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, scheme string) (*xio.Opened, error) {
	host, port, path, err := wsTarget(s, false)
	if err != nil {
		return nil, err
	}
	network := xio.ConnectNetworkForType(g, s, host, "tcp")
	u := url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(xio.StripBrackets(host), port),
		Path:   path,
	}

	timeout := xio.ConnectTimeout(s)
	var tlsCfg *tls.Config
	if scheme == "wss" {
		tlsCfg, err = tlsopen.TLSClientConfig(s, host)
		if err != nil {
			return nil, err
		}
	}

	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		err := xio.WithRetry(dctx, s, g, s.Type, func() error {
			cctx := dctx
			var cancel context.CancelFunc
			if timeout > 0 {
				cctx, cancel = context.WithTimeout(dctx, timeout)
				defer cancel()
			}
			nc, e := dialWS(cctx, network, host, port, u.String(), s, g, tlsCfg)
			if e != nil {
				return e
			}
			conn = nc
			return nil
		})
		return conn, err
	}

	return xio.OpenDialed(ctx, s, g, xio.Dialed{
		Label:       s.Type + ":" + u.Host + path,
		Dial:        dialOnce,
		RememberTLS: scheme == "wss",
	})
}

func dialWS(ctx context.Context, network, host, port, rawURL string, s parse.Spec, g *xio.Global, tlsCfg *tls.Config) (net.Conn, error) {
	tr := &http.Transport{
		DialContext: func(dctx context.Context, _, _ string) (net.Conn, error) {
			c, e := xio.DialTCPAll(dctx, network, xio.StripBrackets(host), port, s, g, xio.ConnectTimeout(s), nil)
			if e != nil {
				return nil, e
			}
			xio.ApplyTCPConnOpts(s, c)
			return c, nil
		},
	}
	if tlsCfg != nil {
		tr.TLSClientConfig = tlsCfg
	}
	opts := &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: tr},
	}
	if origin := s.OptionValue("origin", ""); origin != "" {
		opts.HTTPHeader = make(http.Header)
		opts.HTTPHeader.Set("Origin", origin)
	}
	if proto := s.OptionValue("protocol", ""); proto != "" {
		opts.Subprotocols = []string{proto}
	}
	c, _, err := websocket.Dial(ctx, rawURL, opts)
	if err != nil {
		return nil, err
	}
	// Background: NetConn must outlive the dial timeout; Close ends the session.
	return websocket.NetConn(context.Background(), c, websocket.MessageBinary), nil
}
