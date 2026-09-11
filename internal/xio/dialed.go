package xio

import (
	"context"
	"github.com/oittaa/socat/internal/addrconfig"
	"net"

	"github.com/oittaa/socat/internal/logx"
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
	Cleanup     []func()
}

// OpenDialed opens a client address: CONNECT,fork loop, or one dial + wrap.
func OpenDialed(ctx context.Context, s addrconfig.Address, g *Global, d Dialed) (*Opened, error) {
	o := &Opened{Label: d.Label}
	for _, f := range d.Cleanup {
		if f != nil {
			o.AddCleanup(f)
		}
	}
	fork, maxChildren, err := ForkLimits(s)
	if err != nil {
		logx.CloseQuiet(o)
		return nil, err
	}
	wrap := d.Wrap
	if wrap == nil {
		wrap = DefaultWrapDial(s)
	}
	if fork {
		o.Kind = KindDial
		o.MaxChildren = maxChildren
		o.Interval = RetryPolicyFromContext(ctx).Interval
		dial := carryPreparedConfig(ctx, d.Dial)
		config := s
		o.Dial = WrapNetNSDial(netNamespaceName(config), g, dial)
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

func carryPreparedConfig(openCtx context.Context, dial func(context.Context) (net.Conn, error)) func(context.Context) (net.Conn, error) {
	if dial == nil {
		return nil
	}
	config, ok := PreparedConfig(openCtx)
	if !ok {
		return dial
	}
	return func(dialCtx context.Context) (net.Conn, error) {
		return dial(withPreparedConfig(dialCtx, config))
	}
}
