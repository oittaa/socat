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
// listeners. Fork returns a KindListen parent. Non-fork accepts one permitted
// peer and returns KindReady.
type ListenSession struct {
	Listener               net.Listener
	Label                  string
	WrapDial               func(net.Conn) (relay.Stream, error)
	HandshakeTimeout       time.Duration
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
		peerFilter, err = PreparedPeerFilter(ctx, s, g)
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

	NoteListenBound(ln.Addr())

	if fork {
		o := &Opened{
			Kind:             KindListen,
			Listener:         ln,
			Label:            sess.Label,
			PeerFilter:       peerFilter.AllowConn,
			MaxChildren:      maxChildren,
			WrapDial:         wrap,
			HandshakeTimeout: sess.HandshakeTimeout,
			AcceptTimeout:    AcceptTimeout(s),
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
			if g != nil && g.Log != nil {
				g.Log.Noticef("%s", err)
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
		g.Log.Infof("accepted connection from %s", conn.RemoteAddr())
	}
	RememberAddrs(g, conn)
	if sess.AfterAccept != nil {
		if err := sess.AfterAccept(g, conn); err != nil {
			logx.CloseQuiet(conn)
			_ = safeCloseLn()
			return nil, err
		}
	}
	st, err := wrap(conn)
	if err != nil {
		logx.CloseQuiet(conn)
		_ = safeCloseLn()
		return nil, err
	}
	o := &Opened{Kind: KindReady, Label: sess.Label, Stream: st}
	if sess.KeepListenerForSession {
		o.AddCleanup(func() { _ = safeCloseLn() })
	}
	return o, nil
}

var (
	listenBoundHookMu sync.Mutex
	listenBoundHook   func(net.Addr)
)

// SetListenBoundTestHook installs a test-only callback fired after a listener
// is bound and before accept or the first datagram. The callback receives the
// bound address so tests can use port 0. The returned function restores the
// previous hook.
func SetListenBoundTestHook(h func(net.Addr)) func() {
	listenBoundHookMu.Lock()
	prev := listenBoundHook
	listenBoundHook = h
	listenBoundHookMu.Unlock()
	return func() {
		listenBoundHookMu.Lock()
		listenBoundHook = prev
		listenBoundHookMu.Unlock()
	}
}

// NoteListenBound fires the test hook after a bind. Stream sessions call this
// from OpenListenSession. Datagram openers that bind without that helper call
// it after ListenUDP so non-fork tests can learn an ephemeral port.
func NoteListenBound(addr net.Addr) {
	listenBoundHookMu.Lock()
	h := listenBoundHook
	listenBoundHookMu.Unlock()
	if h != nil {
		h(addr)
	}
}
