package quicopen

import (
	"context"
	"fmt"
	"net"

	"github.com/quic-go/quic-go"

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
		_ = tr.Close()
		_ = pc.Close()
		return nil, fmt.Errorf("%s: option max-children not allowed without option fork", s.Type)
	}

	o := &xio.Opened{
		Label: s.Type + ":" + dest,
	}
	o.AddCleanup(func() {
		_ = tr.Close()
		_ = pc.Close()
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
