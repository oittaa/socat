package proxyopen

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/tlsopen"
)

func dialH2CONNECT(ctx context.Context, s addrconfig.Address, g *xio.Global, t proxyTarget) (net.Conn, error) {
	h2c := s.Proxy.H2C.Value
	connectTimeout := xio.ConnectTimeout(s)
	handshakeTimeout := xio.HandshakeTimeout(s)
	network := xio.ConnectNetworkForType(s, t.proxyHost, "tcp")

	var tlsCfg *tls.Config
	scheme := "https"
	if h2c {
		scheme = "http"
	} else {
		cfg, err := tlsopen.TLSClientConfigSettings(s.Type, s.TLS, t.proxyHost.String())
		if err != nil {
			return nil, err
		}
		tlsCfg = cfg.Clone()
		tlsCfg.NextProtos = []string{proxyALPN(s.TLS, "h2")}
	}

	proxyPort, err := xio.ResolvePort("tcp", t.proxyPort)
	if err != nil {
		return nil, err
	}
	u := scheme + "://" + proxyCONNECTTarget(t.proxyHost.String(), proxyPort) + "/"
	authority := proxyCONNECTTarget(t.connectHost, t.connectPort)

	var conn net.Conn
	err = xio.WithRetry(ctx, g, s.Common.Retry.Policy(), "PROXY-CONNECT", func() error {
		raw, e := xio.DialTCPAll(ctx, xio.DialTarget{Network: network, Host: s.Proxy.Server, Port: proxyPortTarget(s.Proxy)}, s, g, connectTimeout, nil)
		if e != nil {
			return e
		}
		sc, ok := raw.(syscall.Conn)
		if !ok {
			logx.CloseQuiet(raw)
			return fmt.Errorf("HTTP/2 proxy transport does not expose a descriptor")
		}
		if e := xio.ApplyFDLifecycleToConn(sc, s); e != nil {
			logx.CloseQuiet(raw)
			return e
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

		e = xio.WithHandshakeDeadline(raw, handshakeTimeout, func() error {
			take := xio.SingleUseDialer(raw, fmt.Errorf("proxy TCP connection already used"))
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

			opened, e := openCONNECTTunnel(connectTunnel{
				roundTrip: tr,
				handshake: hctx,
				stopTimer: stopTimer,
				proxy:     s.Proxy,
				url:       u,
				authority: authority,
				network:   "h2",
				closers: []io.Closer{closerFunc(func() error {
					cancelHandshake()
					tr.CloseIdleConnections()
					return nil
				})},
			})
			if e != nil {
				tr.CloseIdleConnections()
				return e
			}
			conn = opened
			return nil
		})
		if e != nil {
			return e
		}
		success = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return conn, nil
}
