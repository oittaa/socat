package wsopen

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/coder/websocket"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/tlsopen"
)

func openWSConnect(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if err := tlsopen.RejectHiddenTLSOnPlaintext(s.Type, s.TLS); err != nil {
		return nil, err
	}
	return openWSConnectScheme(ctx, s, mode, g, "ws")
}

func openWSSConnect(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openWSConnectScheme(ctx, s, mode, g, "wss")
}

func openWSConnectScheme(ctx context.Context, s addrconfig.Address, _ xio.Mode, g *xio.Global, scheme string) (*xio.Opened, error) {
	_, _, path, err := wsTarget(s, false)
	if err != nil {
		return nil, err
	}
	dest := wsDialTarget{
		Network: xio.ConnectNetworkForType(g, s, s.Network.Target, "tcp"),
		Scheme:  scheme,
		Host:    s.Network.Target,
		Port:    s.Network.TargetPort,
		Path:    path,
	}
	u := dest.httpURL()

	handshakeTimeout := xio.HandshakeTimeout(s)
	var tlsCfg *tls.Config
	if scheme == "wss" {
		tlsCfg, err = tlsopen.TLSClientConfigSettings(s.Type, s.TLS, s.Network.Target.String())
		if err != nil {
			return nil, err
		}
	}

	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		err := xio.WithRetry(dctx, g, s.Common.Retry.Policy(), s.Type, func() error {
			nc, e := dialWS(dctx, dest, s, g, tlsCfg, handshakeTimeout)
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
			return xio.SetupConnectedStream(s, relay.NetStream{Conn: c})
		},
	})
}

// wsDialTarget is the TCP peer and the WebSocket URL built from it.
type wsDialTarget struct {
	Network string
	Scheme  string
	Host    addrconfig.HostTarget
	Port    addrconfig.PortTarget
	Path    string
}

func (t wsDialTarget) httpURL() url.URL {
	port := t.Port.Text()
	if t.Port.Numeric {
		port = strconv.Itoa(int(t.Port.Number))
	}
	return url.URL{
		Scheme: t.Scheme,
		Host:   net.JoinHostPort(t.Host.String(), port),
		Path:   t.Path,
	}
}

func dialWS(ctx context.Context, dest wsDialTarget, s addrconfig.Address, g *xio.Global, tlsCfg *tls.Config, handshakeTimeout time.Duration) (net.Conn, error) {
	raw, err := xio.DialTCPAll(ctx, xio.DialTarget{Network: dest.Network, Host: s.Network.Target, Port: s.Network.TargetPort}, s, g, xio.ConnectTimeout(s), nil)
	if err != nil {
		return nil, err
	}
	owned := false
	defer func() {
		if !owned {
			logx.CloseQuiet(raw)
		}
	}()

	u := dest.httpURL()
	rawURL := u.String()
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
		if origin := s.TLS.WSOrigin.Value; origin != "" {
			opts.HTTPHeader = make(http.Header)
			opts.HTTPHeader.Set("Origin", origin)
		}
		if proto := s.TLS.WSProtocol.Value; proto != "" {
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
