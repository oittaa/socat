package quicopen

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/quic"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/tlsopen"
)

func openQUICListen(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
	_, port, err := quicTarget(s, true)
	if err != nil {
		return nil, err
	}
	network := udpNetwork(xio.ListenNetwork(g, s))
	if network == "udp6" && s.HasOption("ipv6-v6only") && !s.BoolOption("ipv6-v6only") {
		network = "udp"
	}
	host := s.OptionValue("bind", "")
	if host == "" {
		switch network {
		case "udp4":
			host = "0.0.0.0"
		default:
			host = "::"
		}
	}
	if network == "udp4" && (host == "::" || host == "") {
		host = "0.0.0.0"
	}
	addr := net.JoinHostPort(xio.StripBrackets(host), port)

	tlsCfg, err := tlsopen.TLSServerConfig(s)
	if err != nil {
		return nil, err
	}
	qcfg := quicConfig(s, tlsCfg)

	pc, err := listenPacket(ctx, network, addr, s)
	if err != nil {
		return nil, err
	}
	ep, err := quic.NewEndpoint(pc, qcfg)
	if err != nil {
		pc.Close()
		return nil, err
	}

	ln := newQUICListener(ctx, ep)
	fork := s.BoolOption("fork")
	maxChildren := 0
	if v := s.OptionValue("max-children", ""); v != "" {
		if n, e := xio.ParsePositiveInt(v); e == nil {
			maxChildren = n
		}
	}
	filter := func(c net.Conn) error { return xio.PeerAllowedG(s, c, g) }
	wrapConn := func(c net.Conn) (relay.Stream, error) {
		return xio.WrapCommon(s, relay.NetStream{Conn: c})
	}

	o := &xio.Opened{
		Listener:    ln,
		Fork:        fork,
		Label:       s.Type + ":" + port,
		PeerFilter:  filter,
		MaxChildren: maxChildren,
		WrapDial:    wrapConn,
	}
	o.AddCleanup(func() { _ = ln.Close() })

	if fork {
		go func() {
			<-ctx.Done()
			_ = ln.Close()
		}()
		return o, nil
	}

	if g != nil && g.Log != nil {
		g.Log.Noticef("listening on %s (quic)", ln.Addr())
	}
	actx := ctx
	var cancel context.CancelFunc
	if at := xio.AcceptTimeout(s); at > 0 {
		actx, cancel = context.WithTimeout(ctx, at)
		defer cancel()
	}
	var conn net.Conn
	for {
		c, err := ln.AcceptContext(actx)
		if err != nil {
			_ = ln.Close()
			o.Listener = nil
			if errors.Is(err, context.DeadlineExceeded) || xio.IsTimeoutErr(err) {
				return nil, xio.ErrAcceptTimeout
			}
			return nil, err
		}
		if err := filter(c); err != nil {
			if g != nil && g.Log != nil {
				g.Log.Noticef("%s", err)
			}
			xio.CloseRefusedPeer(c)
			continue
		}
		conn = c
		break
	}
	o.Listener = nil
	xio.RememberAddrs(g, conn)
	st, err := wrapConn(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	o.Stream = st
	return o, nil
}

func quicConfig(s parse.Spec, tlsCfg *tls.Config) *quic.Config {
	cfg := &quic.Config{
		TLSConfig: withALPN(tlsCfg, s),
	}
	if t := xio.ConnectTimeout(s); t > 0 {
		cfg.HandshakeTimeout = t
	}
	return cfg
}

func listenPacket(ctx context.Context, network, addr string, s parse.Spec) (net.PacketConn, error) {
	reuse := true
	if s.HasOption("reuseaddr") {
		reuse = s.BoolOption("reuseaddr")
	}
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if reuse {
					_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				}
				if network == "udp" || network == "udp6" {
					if s.HasOption("ipv6-v6only") {
						v := 0
						if s.BoolOption("ipv6-v6only") {
							v = 1
						}
						_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, v)
					} else if network == "udp" {
						_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0)
					}
				}
			})
		},
	}
	return lc.ListenPacket(ctx, network, addr)
}

type quicListener struct {
	ep     *quic.Endpoint
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
}

func newQUICListener(parent context.Context, ep *quic.Endpoint) *quicListener {
	ctx, cancel := context.WithCancel(parent)
	return &quicListener{ep: ep, ctx: ctx, cancel: cancel}
}

func (l *quicListener) Accept() (net.Conn, error) {
	return l.AcceptContext(l.ctx)
}

func (l *quicListener) AcceptContext(ctx context.Context) (net.Conn, error) {
	qc, err := l.ep.Accept(ctx)
	if err != nil {
		return nil, err
	}
	st, err := qc.AcceptStream(ctx)
	if err != nil {
		_ = qc.Close()
		return nil, err
	}
	return wrapQUIC(qc, st), nil
}

func (l *quicListener) Close() error {
	var err error
	l.once.Do(func() {
		l.cancel()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err = l.ep.Close(ctx)
	})
	return err
}

func (l *quicListener) Addr() net.Addr {
	return udpAddr(l.ep.LocalAddr())
}
