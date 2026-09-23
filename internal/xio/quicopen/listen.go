package quicopen

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/oittaa/socat/internal/addrconfig"
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
	queue  *acceptQueue
}

func newQUICListener(parent context.Context, ln *quic.Listener, pc net.PacketConn, mode xio.Mode) *quicListener {
	ctx, cancel := context.WithCancel(parent)
	l := &quicListener{
		ln: ln, pc: pc, mode: mode, ctx: ctx, cancel: cancel,
		queue: newAcceptQueue(),
	}
	go l.acceptConnections()
	return l
}

// acceptConnections keeps accepting connections while each stream wait runs
// on its own. Otherwise one peer that never opens a stream blocks Accept.
func (l *quicListener) acceptConnections() {
	err := net.ErrClosed
	defer func() { l.queue.fail(err) }()
	for {
		qc, aerr := l.ln.Accept(l.ctx)
		if aerr != nil {
			err = aerr
			return
		}
		if l.queue.isClosed() {
			_ = qc.CloseWithError(0, "")
			continue
		}
		go l.acceptStream(qc)
	}
}

func (l *quicListener) acceptStream(qc *quic.Conn) {
	st, err := qc.AcceptStream(l.ctx)
	if err != nil {
		_ = qc.CloseWithError(0, "")
		return
	}
	nc := wrapQUIC(qc, st)
	nc.waitPeerClose = l.mode == xio.ModeWrite
	if !l.queue.push(nc) {
		_ = nc.Close()
	}
}

func (l *quicListener) Accept() (net.Conn, error) {
	return l.AcceptContext(l.ctx)
}

func (l *quicListener) AcceptContext(ctx context.Context) (net.Conn, error) {
	return l.queue.pop(ctx)
}

// acceptQueue delivers conns whose streams are already open.
type acceptQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	conns  []net.Conn
	err    error
	closed bool
}

func newAcceptQueue() *acceptQueue {
	q := &acceptQueue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *acceptQueue) isClosed() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.closed
}

func (q *acceptQueue) push(c net.Conn) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return false
	}
	q.conns = append(q.conns, c)
	q.cond.Signal()
	return true
}

func (q *acceptQueue) fail(err error) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.closed = true
	q.err = err
	pending := q.conns
	q.conns = nil
	q.cond.Broadcast()
	q.mu.Unlock()
	for _, c := range pending {
		_ = c.Close()
	}
}

func (q *acceptQueue) pop(ctx context.Context) (net.Conn, error) {
	stop := context.AfterFunc(ctx, func() {
		q.mu.Lock()
		q.cond.Broadcast()
		q.mu.Unlock()
	})
	q.mu.Lock()
	for len(q.conns) == 0 && !q.closed && ctx.Err() == nil {
		q.cond.Wait()
	}
	var (
		c   net.Conn
		err error
	)
	switch {
	case len(q.conns) > 0 && !q.closed && ctx.Err() == nil:
		c = q.conns[0]
		q.conns[0] = nil
		q.conns = q.conns[1:]
	case ctx.Err() != nil:
		err = ctx.Err()
	case q.err != nil:
		err = q.err
	default:
		err = net.ErrClosed
	}
	q.mu.Unlock()
	stop()
	return c, err
}

func (l *quicListener) Close() error {
	var err error
	l.once.Do(func() {
		l.cancel()
		l.queue.fail(net.ErrClosed)
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
