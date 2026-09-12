package quicopen

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/oittaa/socat/internal/addrconfig"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/tlsopen"
)

func openQUICListen(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	_, port, err := quicTarget(s, true)
	if err != nil {
		return nil, err
	}
	network := xio.TCPToUDPNetwork(xio.ListenNetwork(g.Options(), s))
	network = xio.DualStackListenNetwork(s, network)
	host, err := xio.ListenBindHost(s, network)
	if err != nil {
		return nil, err
	}

	tlsCfg, err := tlsopen.TLSServerConfigSettings(s.Type, s.TLS)
	if err != nil {
		return nil, err
	}
	qcfg, err := quicConfig(ctx, s, tlsCfg)
	if err != nil {
		return nil, err
	}

	pc, err := listenPacket(ctx, network, host, s.Network.ListenPort, s)
	if err != nil {
		return nil, err
	}
	qln, err := quic.Listen(pc, qcfg.tls, qcfg.cfg)
	if err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}

	ln := newQUICListener(ctx, qln, pc, mode)
	return xio.OpenListenSession(ctx, s, g, xio.ListenSession{
		Listener:               ln,
		Label:                  s.Type + ":" + port,
		WrapDial:               xio.DefaultWrapOpened(s),
		KeepListenerForSession: true,
		ListeningLog:           fmt.Sprintf("listening on %s (quic)", ln.Addr()),
	})
}

type quicSetup struct {
	tls *tls.Config
	cfg *quic.Config
}

func quicHandshakeIdleTimeout(ctx context.Context, s addrconfig.Address) time.Duration {
	return xio.QUICHandshakeIdleTimeout(s)
}

func quicConfig(ctx context.Context, s addrconfig.Address, tlsCfg *tls.Config) (quicSetup, error) {
	quicTLS, err := withALPN(tlsCfg, alpnProto(s.TLS))
	if err != nil {
		return quicSetup{}, err
	}
	// HandshakeIdleTimeout is the handshake-timeout extra (no C equivalent).
	// Do not reuse connect-timeout as the QUIC handshake idle bound.
	// handshake-timeout=0 must not become quic-go's 5s default.
	cfg := &quic.Config{HandshakeIdleTimeout: quicHandshakeIdleTimeout(ctx, s)}
	return quicSetup{tls: quicTLS, cfg: cfg}, nil
}

func listenPacket(ctx context.Context, network string, host addrconfig.HostTarget, port addrconfig.PortTarget, s addrconfig.Address) (net.PacketConn, error) {
	return xio.ListenPacketWithOptions(ctx, network, host, port, s)
}

func listenQUICClientPacket(ctx context.Context, network string, bindHost addrconfig.HostTarget, sourceport addrconfig.PortTarget, s addrconfig.Address, g *xio.Global) (net.PacketConn, error) {
	return xio.ListenClientPacket(ctx, network, bindHost, sourceport, s, g)
}

type quicListener struct {
	ln     *quic.Listener
	pc     net.PacketConn
	mode   xio.Mode
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
}

func newQUICListener(parent context.Context, ln *quic.Listener, pc net.PacketConn, mode xio.Mode) *quicListener {
	ctx, cancel := context.WithCancel(parent)
	return &quicListener{ln: ln, pc: pc, mode: mode, ctx: ctx, cancel: cancel}
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
	nc := wrapQUIC(qc, st)
	nc.waitPeerClose = l.mode == xio.ModeWrite
	return nc, nil
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
