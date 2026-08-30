package quicopen

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/tlsopen"
)

// quicDialAttemptTimeout is the per-retry context timeout for Transport.Dial
// and OpenStreamSync. connect-timeout (when > 0) caps the whole remote
// establishment attempt. handshake-timeout (when > 0, including the 30s
// omitted default) is also a candidate; handshake-timeout=0 disables only
// that handshake candidate. The earlier positive deadline wins. A zero
// result means no extra Dial context timeout.
func quicDialAttemptTimeout(s parse.Spec) time.Duration {
	return xio.CombinedConnectHandshakeTimeout(s)
}

func openQUICConnect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	host, port, err := quicTarget(s, false)
	if err != nil {
		return nil, err
	}
	network := udpNetwork(xio.ConnectNetworkForType(g, s, host, "tcp"))
	dest := net.JoinHostPort(xio.StripBrackets(host), port)
	netw, err := xio.PacketNetworkForHost(ctx, s, network, host)
	if err != nil {
		return nil, err
	}
	network = netw

	tlsCfg, err := tlsopen.TLSClientConfig(s, host)
	if err != nil {
		return nil, err
	}
	setup, err := quicConfig(s, tlsCfg)
	if err != nil {
		return nil, err
	}

	bindHost, err := xio.ListenBindHost(s, network, s.OptionValue("bind", ""))
	if err != nil {
		return nil, err
	}
	pc, err := listenQUICClientPacket(ctx, network, bindHost, s.OptionValue("sourceport", ""), s, g)
	if err != nil {
		return nil, err
	}
	tr := &quic.Transport{Conn: pc}

	// Set when any connection on this transport carried payload or a FIN;
	// teardown then waits out the drain so tail bytes and the FIN survive.
	var drain atomic.Bool

	attemptTimeout := quicDialAttemptTimeout(s)
	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		err := xio.WithRetry(dctx, s, g, s.Type, func() error {
			cctx := dctx
			var cancel context.CancelFunc
			// Transport.Dial does path setup and the TLS handshake.
			// connect-timeout and handshake-timeout share that budget
			// (handshake-timeout=0 drops only the handshake candidate).
			if attemptTimeout > 0 {
				cctx, cancel = context.WithTimeout(dctx, attemptTimeout)
				defer cancel()
			}
			raddr, e := xio.ResolveUDPAddr(cctx, s, network, dest)
			if e != nil {
				return e
			}
			qc, e := tr.Dial(cctx, raddr, setup.tls.Clone(), setup.cfg)
			xio.ReportQUICUDPBufferCap(pc, logFromGlobal(g))
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

	o := &xio.Opened{Label: s.Type + ":" + dest}
	o.AddCleanup(func() {
		if drain.Load() {
			time.AfterFunc(quicConnDrain, func() {
				_ = tr.Close()
				_ = pc.Close()
			})
			return
		}
		_ = tr.Close()
		_ = pc.Close()
	})
	opened, err := xio.OpenDialed(ctx, s, g, xio.Dialed{
		Dial: dialOnce,
		Base: o,
	})
	if err != nil {
		logx.CloseQuiet(o)
		return nil, err
	}
	return opened, nil
}
