package proxyopen

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/oittaa/socat/internal/addrconfig"
	"io"
	"net"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/tlsopen"
)

// testHookH3PacketConn, when set, sees the HTTP/3 UDP PacketConn after
// ListenControl socket options and before QUIC dials on it.
var testHookH3PacketConn func(net.PacketConn)

// listenH3Packet binds the HTTP/3 UDP socket with ListenControl so send-side
// IP/ancillary options apply after socket() and before bind, instead of
// http3.Transport creating its own UDP socket and ignoring those options.
func listenH3Packet(ctx context.Context, s addrconfig.Address, g *xio.Global, proxyHost addrconfig.HostTarget) (net.PacketConn, string, error) {
	network := xio.TCPToUDPNetwork(xio.ConnectNetworkForType(g, s, proxyHost, "tcp"))
	netw, err := xio.PacketNetworkForHost(ctx, s, network, proxyHost)
	if err != nil {
		return nil, "", err
	}
	network = netw
	bindHost, err := xio.ListenBindHost(s, network)
	if err != nil {
		return nil, "", err
	}
	pc, err := xio.ListenClientPacket(ctx, network, bindHost, xio.ClientLocalPort(s), s, g)
	if err != nil {
		return nil, "", err
	}
	return pc, network, nil
}

func dialH3CONNECT(ctx context.Context, s addrconfig.Address, g *xio.Global, t proxyTarget) (net.Conn, error) {
	tlsCfg, err := tlsopen.TLSClientConfigSettings(s.Type, s.TLS, t.proxyHost.String())
	if err != nil {
		return nil, err
	}
	tlsCfg = tlsCfg.Clone()
	if tlsCfg.MinVersion < tls.VersionTLS13 {
		tlsCfg.MinVersion = tls.VersionTLS13
	}
	tlsCfg.NextProtos = []string{proxyALPN(s.TLS, http3.NextProtoH3)}

	proxyPort, err := xio.ResolvePort("udp", t.proxyPort)
	if err != nil {
		return nil, err
	}
	u := "https://" + proxyCONNECTTarget(t.proxyHost.String(), proxyPort) + "/"
	authority := proxyCONNECTTarget(t.connectHost, t.connectPort)
	attemptTimeout := xio.CombinedConnectHandshakeTimeout(s)
	idle := xio.QUICHandshakeIdleTimeout(s)

	var conn net.Conn
	err = xio.WithRetry(ctx, g, "PROXY-CONNECT", func() error {
		cctx, stopTimer, cancelHandshake := proxyHandshakeContext(ctx, attemptTimeout)
		pc, network, e := listenH3Packet(cctx, s, g, t.proxyHost)
		if e != nil {
			stopTimer()
			cancelHandshake()
			return e
		}
		if h := testHookH3PacketConn; h != nil {
			h(pc)
		}
		qtr := &quic.Transport{Conn: pc}
		tr := &http3.Transport{
			TLSClientConfig: tlsCfg.Clone(),
			QUICConfig:      &quic.Config{HandshakeIdleTimeout: idle},
			Dial: func(dctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				raddr, resolveErr := xio.ResolveUDPTarget(dctx, s, network, t.proxyHost, t.proxyPort)
				if resolveErr != nil {
					return nil, resolveErr
				}
				return qtr.Dial(dctx, raddr, tlsCfg, cfg)
			},
		}
		closeH3 := func() error {
			cancelHandshake()
			return errors.Join(tr.Close(), qtr.Close(), pc.Close())
		}
		success := false
		defer func() {
			if !success {
				stopTimer()
				_ = closeH3()
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
		if auth, e := proxyAuthString(s.Proxy); e != nil {
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
			extra:  []io.Closer{closerFunc(closeH3)},
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return conn, nil
}
