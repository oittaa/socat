package xio

import (
	"context"
	"net"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// Dialed is a completed connect (including handshake) plus optional wrap.
type Dialed struct {
	Label       string
	Dial        func(context.Context) (net.Conn, error)
	Wrap        func(net.Conn) (relay.Stream, error) // also WrapDial when fork
	RememberTLS bool
	LogOK       bool
	LogSuffix   string
	Base        *Opened
}

// OpenDialed opens a client address: CONNECT,fork loop, or one dial + wrap.
func OpenDialed(ctx context.Context, s parse.Spec, g *Global, d Dialed) (*Opened, error) {
	fork, maxChildren, err := ForkLimits(s)
	if err != nil {
		return nil, err
	}
	o := d.Base
	if o == nil {
		o = &Opened{}
	}
	if o.Label == "" {
		o.Label = d.Label
	}
	wrap := d.Wrap
	if wrap == nil {
		wrap = DefaultWrapDial(s)
	}
	if fork {
		o.Kind = KindDial
		o.MaxChildren = maxChildren
		o.Interval = ParseRetry(s).Interval
		o.Dial = WrapNetNSDial(s, g, d.Dial)
		o.WrapDial = wrap
		return o, nil
	}
	conn, err := d.Dial(ctx)
	if err != nil {
		logx.CloseQuiet(o)
		return nil, err
	}
	RememberAddrs(g, conn)
	if d.RememberTLS {
		if err := RememberTLSPeer(g, conn, HandshakeTimeout(s)); err != nil {
			logx.CloseQuiet(conn)
			logx.CloseQuiet(o)
			return nil, err
		}
	}
	if d.LogOK && g != nil && g.Log != nil {
		g.Log.Infof("successfully connected from %s to %s%s", conn.LocalAddr(), conn.RemoteAddr(), d.LogSuffix)
	}
	st, err := wrap(conn)
	if err != nil {
		logx.CloseQuiet(conn)
		logx.CloseQuiet(o)
		return nil, err
	}
	o.Stream = st
	return o, nil
}
