package quicopen

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/quic"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/tlsopen"
)

func openQUICConnect(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
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
	qcfg := quicConfig(s, tlsCfg)

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
	// nil listen config: this endpoint does not accept inbound connections.
	ep, err := quic.NewEndpoint(pc, nil)
	if err != nil {
		pc.Close()
		return nil, err
	}

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
			qc, e := ep.Dial(cctx, network, dest, qcfg)
			if e != nil {
				return e
			}
			st, e := qc.NewStream(cctx)
			if e != nil {
				_ = qc.Close()
				return e
			}
			conn = wrapQUIC(qc, st)
			return nil
		})
		return conn, err
	}

	fork := s.BoolOption("fork")
	maxChildren := 0
	if v := s.OptionValue("max-children", ""); v != "" {
		if n, e := xio.ParsePositiveInt(v); e == nil {
			maxChildren = n
		}
	}
	if maxChildren > 0 && !fork {
		_ = ep.Close(context.Background())
		return nil, fmt.Errorf("%s: option max-children not allowed without option fork", s.Type)
	}

	o := &xio.Opened{
		Label: s.Type + ":" + dest,
	}
	o.AddCleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = ep.Close(ctx)
	})

	if fork {
		o.ConnectFork = true
		o.Fork = true
		o.MaxChildren = maxChildren
		o.Interval = xio.ParseRetry(s).Interval
		o.Dial = dialOnce
		return o, nil
	}

	conn, err := dialOnce(ctx)
	if err != nil {
		o.Close()
		return nil, err
	}
	xio.RememberAddrs(g, conn)
	st := relay.Stream(relay.NetStream{Conn: conn})
	st, err = xio.WrapCommon(s, st)
	if err != nil {
		conn.Close()
		o.Close()
		return nil, err
	}
	o.Stream = st
	return o, nil
}
