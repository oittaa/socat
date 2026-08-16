package quicopen

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"github.com/quic-go/quic-go"

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
	host := xio.ListenBindHost(network, s.OptionValue("bind", ""))
	if network == "udp4" && host == "::" {
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
	qln, err := quic.Listen(pc, qcfg.tls, qcfg.cfg)
	if err != nil {
		_ = pc.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}

	ln := newQUICListener(ctx, qln, pc)
	fork, maxChildren := xio.ForkLimits(s)
	filter := func(c net.Conn) error { return xio.PeerAllowedG(s, c, g) }
	wrapConn := func(c net.Conn) (relay.Stream, error) {
		return xio.WrapCommon(s, relay.NetStream{Conn: c})
	}

	o := &xio.Opened{
		Kind:        xio.ListenKind(fork),
		Listener:    ln,
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
		_ = conn.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	o.Stream = st
	return o, nil
}

type quicSetup struct {
	tls *tls.Config
	cfg *quic.Config
}

func quicConfig(s parse.Spec, tlsCfg *tls.Config) quicSetup {
	cfg := &quic.Config{}
	if t := xio.ConnectTimeout(s); t > 0 {
		cfg.HandshakeIdleTimeout = t
	}
	return quicSetup{tls: withALPN(tlsCfg, s), cfg: cfg}
}

func listenPacket(ctx context.Context, network, addr string, s parse.Spec) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: xio.ListenControl(s)}
	return lc.ListenPacket(ctx, network, addr)
}

type quicListener struct {
	ln     *quic.Listener
	pc     net.PacketConn
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
}

func newQUICListener(parent context.Context, ln *quic.Listener, pc net.PacketConn) *quicListener {
	ctx, cancel := context.WithCancel(parent)
	return &quicListener{ln: ln, pc: pc, ctx: ctx, cancel: cancel}
}

func (l *quicListener) Accept() (net.Conn, error) {
	return l.AcceptContext(l.ctx)
}

func (l *quicListener) AcceptContext(ctx context.Context) (net.Conn, error) {
	qc, err := l.ln.Accept(ctx)
	if err != nil {
		return nil, err
	}
	st, err := qc.AcceptStream(ctx)
	if err != nil {
		_ = qc.CloseWithError(0, "")
		return nil, err
	}
	return wrapQUIC(qc, st), nil
}

func (l *quicListener) Close() error {
	var err error
	l.once.Do(func() {
		l.cancel()
		err = l.ln.Close()
		if l.pc != nil {
			_ = l.pc.Close()
		}
	})
	return err
}

func (l *quicListener) Addr() net.Addr {
	return l.ln.Addr()
}
