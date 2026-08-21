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

func openQUICConnect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	host, port, err := quicTarget(s, false)
	if err != nil {
		return nil, err
	}
	network := udpNetwork(xio.ConnectNetworkForType(g, s, host, "tcp"))
	dest := net.JoinHostPort(xio.StripBrackets(host), port)

	tlsCfg, err := tlsopen.TLSClientConfig(s, host)
	if err != nil {
		return nil, err
	}
	setup := quicConfig(s, tlsCfg)

	bindHost := s.OptionValue("bind", "")
	if bindHost == "" {
		switch network {
		case "udp4":
			bindHost = "0.0.0.0"
		case "udp6":
			bindHost = "::"
		default:
			bindHost = ""
		}
	}
	sp := s.OptionValue("sourceport", "")
	if sp == "" {
		sp = "0"
	}
	laddr := net.JoinHostPort(xio.StripBrackets(bindHost), sp)

	pc, err := listenPacket(ctx, network, laddr, s)
	if err != nil {
		return nil, err
	}
	tr := &quic.Transport{Conn: pc}

	// Set when any connection on this transport carried payload or a FIN;
	// teardown then waits out the drain so tail bytes and the FIN survive.
	var drain atomic.Bool

	timeout := xio.ConnectTimeout(s)
	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		err := xio.WithRetry(dctx, s, g, s.Type, func() error {
			cctx := dctx
			var cancel context.CancelFunc
			if timeout > 0 {
				cctx, cancel = context.WithTimeout(dctx, timeout)
				defer cancel()
			}
			raddr, e := net.ResolveUDPAddr(network, dest)
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
