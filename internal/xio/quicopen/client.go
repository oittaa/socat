package quicopen

import (
	"context"
	"github.com/oittaa/socat/internal/addrconfig"
	"net"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/tlsopen"
)

// quicDialAttemptTimeout is the per-retry context timeout for Transport.Dial
// and OpenStreamSync. connect-timeout (when > 0) caps the whole remote
// establishment attempt. handshake-timeout (when > 0, including the 30s
// omitted default) is also a candidate; handshake-timeout=0 disables only
// that handshake candidate. The earlier positive deadline wins. A zero
// result means no extra Dial context timeout.
func quicDialAttemptTimeout(ctx context.Context, s addrconfig.Address) time.Duration {
	return xio.CombinedConnectHandshakeTimeout(s)
}

func openQUICConnect(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	host, _, err := quicTarget(s, false)
	if err != nil {
		return nil, err
	}
	target := s.Network.Target
	targetPort := s.Network.TargetPort
	network := xio.TCPToUDPNetwork(xio.ConnectNetworkForType(g, s, host, "tcp"))
	dest := net.JoinHostPort(target.String(), targetPort.Text())
	netw, err := xio.PacketNetworkForHost(ctx, s, network, target)
	if err != nil {
		return nil, err
	}
	network = netw

	tlsCfg, err := tlsopen.TLSClientConfigSettings(s.Type, s.TLS, host)
	if err != nil {
		return nil, err
	}
	setup, err := quicConfig(ctx, s, tlsCfg)
	if err != nil {
		return nil, err
	}

	bindHost, err := xio.ListenBindHost(s, network)
	if err != nil {
		return nil, err
	}
	pc, err := listenQUICClientPacket(ctx, network, bindHost, xio.ClientLocalPort(s), s, g)
	if err != nil {
		return nil, err
	}
	tr := &quic.Transport{Conn: pc}

	// Set when any connection on this transport carried payload or a FIN;
	// teardown then waits out the drain so tail bytes and the FIN survive.
	var drain atomic.Bool

	attemptTimeout := quicDialAttemptTimeout(ctx, s)
	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		err := xio.WithRetry(dctx, g, s.Type, func() error {
			cctx := dctx
			var cancel context.CancelFunc
			// Transport.Dial does path setup and the TLS handshake.
			// connect-timeout and handshake-timeout share that budget
			// (handshake-timeout=0 drops only the handshake candidate).
			if attemptTimeout > 0 {
				cctx, cancel = context.WithTimeout(dctx, attemptTimeout)
				defer cancel()
			}
			raddr, e := xio.ResolveUDPTarget(cctx, s, network, target, targetPort)
			if e != nil {
				return e
			}
			qc, e := tr.Dial(cctx, raddr, setup.tls.Clone(), setup.cfg)
			if e != nil {
				return e
			}
			st, e := qc.OpenStreamSync(cctx)
			if e != nil {
				_ = qc.CloseWithError(0, "")
				return e
			}
			// quic-go does not signal OpenStream to the peer until data,
			// reset, or close. A receive-only client never writes, so
			// half-close send and unblock the listener's AcceptStream.
			if mode == xio.ModeRead {
				if e := st.Close(); e != nil {
					_ = qc.CloseWithError(0, "")
					return e
				}
			}
			nc := wrapQUIC(qc, st)
			nc.transportDrain = &drain
			nc.waitPeerClose = mode == xio.ModeWrite
			if mode == xio.ModeRead {
				// The FIN was queued on st directly; record it so Close
				// keeps the drain delay and the FIN is not dropped.
				nc.markFinSent()
			}
			conn = nc
			return nil
		})
		return conn, err
	}

	return xio.OpenDialed(ctx, s, g, xio.Dialed{
		Label: s.Type + ":" + dest,
		Dial:  dialOnce,
		Wrap:  xio.DefaultWrapOpened(s),
		Cleanup: []func(){func() {
			if drain.Load() {
				time.AfterFunc(quicConnDrain, func() {
					_ = tr.Close()
					_ = pc.Close()
				})
				return
			}
			_ = tr.Close()
			_ = pc.Close()
		}},
	})
}
