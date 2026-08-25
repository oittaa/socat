package quicopen

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	"github.com/quic-go/quic-go"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
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
	host, err := xio.ListenBindHost(network, s.OptionValue("bind", ""))
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(xio.StripBrackets(host), port)

	tlsCfg, err := tlsopen.TLSServerConfig(s)
	if err != nil {
		return nil, err
	}
	qcfg, err := quicConfig(s, tlsCfg)
	if err != nil {
		return nil, err
	}

	pc, err := listenPacket(ctx, network, addr, s)
	if err != nil {
		return nil, err
	}
	qln, err := quic.Listen(pc, qcfg.tls, qcfg.cfg)
	if err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}

	ln := newQUICListener(ctx, qln, pc)
	return xio.OpenListenSession(ctx, s, g, xio.ListenSession{
		Listener:               ln,
		Label:                  s.Type + ":" + port,
		Accept:                 func(actx context.Context) (net.Conn, error) { return ln.AcceptContext(actx) },
		UseContextTimeout:      true,
		KeepListenerForSession: true,
		ListeningLog:           fmt.Sprintf("listening on %s (quic)", ln.Addr()),
	})
}

type quicSetup struct {
	tls *tls.Config
	cfg *quic.Config
}

func quicConfig(s parse.Spec, tlsCfg *tls.Config) (quicSetup, error) {
	quicTLS, err := withALPN(tlsCfg, s)
	if err != nil {
		return quicSetup{}, err
	}
	cfg := &quic.Config{}
	if t := xio.ConnectTimeout(s); t > 0 {
		cfg.HandshakeIdleTimeout = t
	}
	return quicSetup{tls: quicTLS, cfg: cfg}, nil
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
