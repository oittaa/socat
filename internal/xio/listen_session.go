package xio

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// ListenSession is the shared accept → peer-filter → wrap path for stream
// listeners. Fork mode keeps Listener+WrapDial+PeerFilter; non-fork accepts
// one permitted peer and applies the same wrap.
type ListenSession struct {
	Listener          net.Listener
	Label             string
	WrapDial          func(net.Conn) (relay.Stream, error)
	SetAcceptDeadline func(time.Time) error
	Accept            func(ctx context.Context) (net.Conn, error)
	UseContextTimeout bool
	HandshakeTimeout  time.Duration
	AfterAccept       func(*Global, net.Conn) error
	ListeningLog      string
	CloseListener     func() error
}

// WrapAccepted applies extra per-conn setup then WrapCommon. Extra may be nil.
func WrapAccepted(s parse.Spec, c net.Conn, extra func(net.Conn) error) (relay.Stream, error) {
	if extra != nil {
		if err := extra(c); err != nil {
			return nil, err
		}
	}
	return WrapCommon(s, relay.NetStream{Conn: c})
}

// DefaultWrapDial returns WrapCommon around a net.Conn.
func DefaultWrapDial(s parse.Spec) func(net.Conn) (relay.Stream, error) {
	return func(c net.Conn) (relay.Stream, error) {
		return WrapCommon(s, relay.NetStream{Conn: c})
	}
}

// OpenListenSession installs fork wrapping and peer filtering, or accepts one
// permitted connection for non-fork. Rejected peers do not restart accept-timeout.
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
		logx.CloseErr(closeLn())
		return nil, err
	}
	wrap := sess.WrapDial
	if wrap == nil {
		wrap = DefaultWrapDial(s)
	}
	filter := func(c net.Conn) error { return PeerAllowedG(s, c, g) }
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
	o.AddCleanup(func() { logx.CloseErr(closeLn()) })

	if fork {
		go func() {
			<-ctx.Done()
			logx.CloseErr(closeLn())
		}()
		return o, nil
	}

	if sess.ListeningLog != "" && g != nil && g.Log != nil {
		g.Log.Noticef("%s", sess.ListeningLog)
	} else if g != nil && g.Log != nil {
		g.Log.Noticef("listening on %s", ln.Addr())
	}

	at := o.AcceptTimeout
	var deadline time.Time
	if at > 0 && !sess.UseContextTimeout {
		deadline = time.Now().Add(at)
	}
	actx := ctx
	var cancel context.CancelFunc
	if sess.UseContextTimeout && at > 0 {
		actx, cancel = context.WithTimeout(ctx, at)
		defer cancel()
	}

	var conn net.Conn
	for {
		if setDeadline != nil && !deadline.IsZero() {
			_ = setDeadline(deadline)
		}
		c, err := acceptOne(actx, ln, accept)
		if err != nil {
			logx.CloseErr(closeLn())
			o.Listener = nil
			if IsTimeoutErr(err) || ctxDeadline(actx, err) {
				if g != nil && g.Log != nil {
					g.Log.Warningf("accept: Connection timed out")
				}
				return nil, ErrAcceptTimeout
			}
			if actx.Err() != nil && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		if err := filter(c); err != nil {
			if g != nil && g.Log != nil {
				g.Log.Noticef("%s", err)
			}
			CloseRefusedPeer(c)
			continue
		}
		conn = c
		break
	}
	logx.CloseErr(closeLn())
	o.Listener = nil
	if g != nil && g.Log != nil && conn.RemoteAddr() != nil {
		g.Log.Infof("accepted connection from %s", conn.RemoteAddr())
	}
	RememberAddrs(g, conn)
	if sess.AfterAccept != nil {
		if err := sess.AfterAccept(g, conn); err != nil {
			logx.CloseQuiet(conn)
			return nil, err
		}
	}
	st, err := wrap(conn)
	if err != nil {
		logx.CloseQuiet(conn)
		return nil, err
	}
	o.Stream = st
	return o, nil
}

func ctxDeadline(ctx context.Context, err error) bool {
	return ctx.Err() != nil && (err == context.DeadlineExceeded || err == ctx.Err())
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
