package xio

import (
	"context"
	"errors"
	"fmt"
	"github.com/oittaa/socat/internal/addrconfig"
	"net"
	"sync"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/relay"
)

// ListenSession is the shared accept → peer-filter → wrap path for stream
// listeners. Fork returns an accept parent. Non-fork accepts one permitted
// peer and returns a ready endpoint.
type ListenSession struct {
	Listener         net.Listener
	Label            string
	WrapDial         func(net.Conn) (relay.Stream, error)
	HandshakeTimeout time.Duration
	// AfterAccept runs after RememberAddrs on each accepted connection,
	// including fork children. Failure closes only that child.
	AfterAccept            func(*Global, net.Conn) error
	ListeningLog           string
	CloseListener          func() error
	KeepListenerForSession bool
	PeerFilter             *PeerFilter
}

// DefaultWrapDial returns SetupStream around a net.Conn.
func DefaultWrapDial(s addrconfig.Address) func(net.Conn) (relay.Stream, error) {
	return func(c net.Conn) (relay.Stream, error) {
		return SetupStream(s, relay.NetStream{Conn: c})
	}
}

// DefaultWrapOpened wraps a net.Conn after the opener applied descriptor
// lifecycle on the real owner.
func DefaultWrapOpened(s addrconfig.Address) func(net.Conn) (relay.Stream, error) {
	return func(c net.Conn) (relay.Stream, error) {
		return WrapOpened(s, relay.NetStream{Conn: c})
	}
}

// OpenListenSession compiles peer filtering before accept, then either
// returns a fork parent or accepts one permitted connection. Each refused peer
// restarts accept-timeout.
func OpenListenSession(ctx context.Context, s addrconfig.Address, g *Global, sess ListenSession) (*Opened, error) {
	ln := sess.Listener
	if ln == nil {
		return nil, fmt.Errorf("listen session requires a listener")
	}
	closeLn := sess.CloseListener
	if closeLn == nil {
		closeLn = ln.Close
	}
	fork, maxChildren, err := ForkLimits(s)
	if err != nil {
		_ = closeLn()
		return nil, err
	}
	wrap := sess.WrapDial
	if wrap == nil {
		wrap = DefaultWrapDial(s)
	}
	peerFilter := sess.PeerFilter
	if peerFilter == nil {
		peerFilter, err = PreparedPeerFilter(ctx, s, g.Options())
		if err != nil {
			_ = closeLn()
			return nil, err
		}
	}

	var closeOnce sync.Once
	safeCloseLn := func() error {
		var err error
		closeOnce.Do(func() {
			err = closeLn()
		})
		return err
	}

	if fork {
		o, err := NewAcceptParent(sess.Label, AcceptParent{
			Listener:         ln,
			PeerFilter:       peerFilter.AllowConn,
			MaxChildren:      maxChildren,
			WrapDial:         wrap,
			HandshakeTimeout: sess.HandshakeTimeout,
			AfterAccept:      sess.AfterAccept,
			AcceptTimeout:    AcceptTimeout(s),
		})
		if err != nil {
			_ = safeCloseLn()
			return nil, err
		}
		o.AddCleanup(func() { _ = safeCloseLn() })
		stop := context.AfterFunc(ctx, func() {
			logx.CloseErr(safeCloseLn())
		})
		o.AddCleanup(func() { stop() })
		return o, nil
	}

	return acceptOnce(ctx, s, g, sess, ln, wrap, peerFilter.AllowConn, safeCloseLn)
}

func acceptOnce(ctx context.Context, s addrconfig.Address, g *Global, sess ListenSession, ln net.Listener, wrap func(net.Conn) (relay.Stream, error), filter func(net.Conn) error, safeCloseLn func() error) (*Opened, error) {
	if sess.ListeningLog != "" && g != nil && g.Log != nil {
		g.Log.Noticef("%s", sess.ListeningLog)
	} else if g != nil && g.Log != nil {
		g.Log.Noticef("listening on %s", ln.Addr())
	}

	at := AcceptTimeout(s)
	abort := func() { _ = safeCloseLn() }
	var conn net.Conn
	for {
		c, err := acceptUntil(ctx, ln, at, abort)
		if err != nil {
			_ = safeCloseLn()
			if ctx != nil && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if errors.Is(err, ErrAcceptTimeout) || IsTimeoutErr(err) {
				if g != nil && g.Log != nil {
					g.Log.Warningf("accept: Connection timed out")
				}
				return nil, ErrAcceptTimeout
			}
			return nil, err
		}
		if err := filter(c); err != nil {
			CloseRefusedPeer(c)
			if ctx != nil && ctx.Err() != nil {
				_ = safeCloseLn()
				return nil, ctx.Err()
			}
			if g != nil {
				LogRefusedPeer(g.Log, err)
			}
			continue
		}
		conn = c
		break
	}
	if !sess.KeepListenerForSession {
		_ = safeCloseLn()
	}
	if g != nil && g.Log != nil && conn.RemoteAddr() != nil {
		g.Log.Noticef("accepted connection from %s", conn.RemoteAddr())
	}
	if err := rememberAccepted(g, conn, sess.AfterAccept); err != nil {
		logx.CloseQuiet(conn)
		_ = safeCloseLn()
		return nil, err
	}
	st, err := wrap(conn)
	if err != nil {
		logx.CloseQuiet(conn)
		_ = safeCloseLn()
		return nil, err
	}
	o, err := NewReady(sess.Label, st)
	if err != nil {
		logx.CloseQuiet(st)
		_ = safeCloseLn()
		return nil, err
	}
	if sess.KeepListenerForSession {
		o.AddCleanup(func() { _ = safeCloseLn() })
	}
	return o, nil
}

// rememberAccepted records generic SOCAT_* address fields, then any
// listen-specific follow-up such as UNIX peer names or TLS metadata.
func rememberAccepted(g *Global, c net.Conn, after func(*Global, net.Conn) error) error {
	RememberAddrs(g, c)
	if after == nil {
		return nil
	}
	return after(g, c)
}
