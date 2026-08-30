package wsopen

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/coder/websocket"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
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

	handshakeTimeout := xio.HandshakeTimeout(s)
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
			nc, e := dialWS(dctx, network, host, port, u.String(), s, g, tlsCfg, handshakeTimeout)
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
		Wrap: func(c net.Conn) (relay.Stream, error) {
			return xio.WrapCommonAfterConnected(s, relay.NetStream{Conn: c})
		},
	})
}

func dialWS(ctx context.Context, network, host, port, rawURL string, s parse.Spec, g *xio.Global, tlsCfg *tls.Config, handshakeTimeout time.Duration) (net.Conn, error) {
	raw, err := xio.DialTCPAll(ctx, network, xio.StripBrackets(host), port, s, g, xio.ConnectTimeout(s), nil)
	if err != nil {
		return nil, err
	}
	owned := false
	defer func() {
		if !owned {
			logx.CloseQuiet(raw)
		}
	}()

	var conn net.Conn
	err = xio.WithHandshakeDeadline(raw, handshakeTimeout, func() error {
		hctx := ctx
		var cancel context.CancelFunc
		if handshakeTimeout > 0 {
			hctx, cancel = context.WithTimeout(ctx, handshakeTimeout)
			defer cancel()
		}

		take := xio.SingleUseDialer(raw, fmt.Errorf("websocket TCP connection already used"))
		var tlsState tls.ConnectionState
		var hasTLSState bool
		tr := &http.Transport{
			DialContext: take,
		}
		if tlsCfg != nil {
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
				tlsState = tc.ConnectionState()
				hasTLSState = true
				return tc, nil
			}
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
		c, _, err := websocket.Dial(hctx, rawURL, opts)
		if err != nil {
			return err
		}
		ws := newWSNetConn(raw, c)
		if hasTLSState {
			ws.rememberTLSState(tlsState)
		}
		conn = ws
		return nil
	})
	if err != nil {
		return nil, err
	}
	owned = true
	return conn, nil
}
