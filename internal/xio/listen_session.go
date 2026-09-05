package xio

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// ListenSession is the shared accept → peer-filter → wrap path for stream
// listeners. Fork mode keeps Listener+WrapDial+PeerFilter; non-fork accepts
// one permitted peer and applies the same wrap.
type ListenSession struct {
	Listener               net.Listener
	Label                  string
	WrapDial               func(net.Conn) (relay.Stream, error)
	SetAcceptDeadline      func(time.Time) error
	Accept                 func(ctx context.Context) (net.Conn, error)
	UseContextTimeout      bool
	HandshakeTimeout       time.Duration
	AfterAccept            func(*Global, net.Conn) error
	ListeningLog           string
	CloseListener          func() error
	KeepListenerForSession bool
	PeerFilter             *PeerFilter
}

// WrapAccepted applies extra per-conn setup then SetupStream. Extra may be nil.
func WrapAccepted(s parse.Spec, c net.Conn, extra func(net.Conn) error) (relay.Stream, error) {
	if extra != nil {
		if err := extra(c); err != nil {
			return nil, err
		}
		return SetupConnectedStream(s, relay.NetStream{Conn: c})
	}
	return SetupStream(s, relay.NetStream{Conn: c})
}

// DefaultWrapDial returns SetupStream around a net.Conn.
func DefaultWrapDial(s parse.Spec) func(net.Conn) (relay.Stream, error) {
	return func(c net.Conn) (relay.Stream, error) {
		return SetupStream(s, relay.NetStream{Conn: c})
	}
}

// OpenListenSession compiles peer filtering before accept, then installs fork
// wrapping or accepts one permitted connection for non-fork. Each refused peer
// restarts accept-timeout.
func OpenListenSession(ctx context.Context, s parse.Spec, g *Global, sess ListenSession) (*Opened, error) {
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
		peerFilter, err = NewPeerFilter(ctx, s, g)
		if err != nil {
			_ = closeLn()
			return nil, err
		}
	}
	filter := peerFilter.AllowConn
	setDeadline := sess.SetAcceptDeadline
	if setDeadline == nil {
		if dl, ok := ln.(interface{ SetDeadline(time.Time) error }); ok {
			setDeadline = dl.SetDeadline
		}
	}
	accept := sess.Accept
	if accept == nil {
		accept = func(context.Context) (net.Conn, error) { return ln.Accept() }
	}

	var closeOnce sync.Once
	safeCloseLn := func() error {
		var err error
		closeOnce.Do(func() {
			err = closeLn()
		})
		return err
	}

	o := &Opened{
		Kind:             ListenKind(fork),
		Listener:         ln,
		Label:            sess.Label,
		PeerFilter:       filter,
		MaxChildren:      maxChildren,
		WrapDial:         wrap,
		HandshakeTimeout: sess.HandshakeTimeout,
	}
	o.AcceptTimeout = AcceptTimeout(s)
	o.AddCleanup(func() { _ = safeCloseLn() })
	NoteListenBound(ln.Addr())

	if fork {
		stop := context.AfterFunc(ctx, func() {
			logx.CloseErr(safeCloseLn())
		})
		o.AddCleanup(func() { stop() })
		return o, nil
	}

	if sess.ListeningLog != "" && g != nil && g.Log != nil {
		g.Log.Noticef("%s", sess.ListeningLog)
	} else if g != nil && g.Log != nil {
		g.Log.Noticef("listening on %s", ln.Addr())
	}

	at := o.AcceptTimeout
	var conn net.Conn
	for {
		if setDeadline != nil && at > 0 && !sess.UseContextTimeout {
			if err := setDeadline(time.Now().Add(at)); err != nil {
				_ = safeCloseLn()
				o.Listener = nil
				return nil, fmt.Errorf("accept-timeout: %w", err)
			}
		}
		actx := ctx
		var cancel context.CancelFunc
		if sess.UseContextTimeout && at > 0 {
			actx, cancel = context.WithTimeout(ctx, at)
		}
		c, err := acceptOne(actx, ln, accept)
		if cancel != nil {
			cancel()
		}
		if err != nil {
			_ = safeCloseLn()
			o.Listener = nil
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if IsTimeoutErr(err) || errors.Is(actx.Err(), context.DeadlineExceeded) {
				if g != nil && g.Log != nil {
					g.Log.Warningf("accept: Connection timed out")
				}
				return nil, ErrAcceptTimeout
			}
			return nil, err
		}
		if err := filter(c); err != nil {
			CloseRefusedPeer(c)
			if ctx.Err() != nil {
				_ = safeCloseLn()
				o.Listener = nil
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
	o.Listener = nil
	if g != nil && g.Log != nil && conn.RemoteAddr() != nil {
		g.Log.Infof("accepted connection from %s", conn.RemoteAddr())
	}
	RememberAddrs(g, conn)
	if sess.AfterAccept != nil {
		if err := sess.AfterAccept(g, conn); err != nil {
			logx.CloseQuiet(conn)
			if sess.KeepListenerForSession {
				_ = safeCloseLn()
			}
			return nil, err
		}
	}
	st, err := wrap(conn)
	if err != nil {
		logx.CloseQuiet(conn)
		if sess.KeepListenerForSession {
			_ = safeCloseLn()
		}
		return nil, err
	}
	o.Stream = st
	return o, nil
}

func acceptOne(ctx context.Context, ln net.Listener, accept func(context.Context) (net.Conn, error)) (net.Conn, error) {
	type acc struct {
		c   net.Conn
		err error
	}
	ch := make(chan acc, 1)
	go func() {
		c, err := accept(ctx)
		ch <- acc{c, err}
	}()
	select {
	case <-ctx.Done():
		_ = ln.Close()
		a := <-ch
		if a.c != nil {
			_ = a.c.Close()
		}
		if a.err != nil && ctx.Err() == nil {
			return nil, a.err
		}
		return nil, ctx.Err()
	case a := <-ch:
		return a.c, a.err
	}
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
