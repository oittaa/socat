package xio

import (
	"context"
	"net"

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
	fork, maxChildren := ForkLimits(s)
	if err := RequireForkWithMaxChildren(s.Type, fork, maxChildren); err != nil {
		return nil, err
	}
	o := d.Base
	if o == nil {
		o = &Opened{}
	}
	if o.Label == "" {
		o.Label = d.Label
	}
	if fork {
		o.ConnectFork = true
		o.Fork = true
		o.MaxChildren = maxChildren
		o.Interval = ParseRetry(s).Interval
		o.Dial = d.Dial
		if d.Wrap != nil {
			o.WrapDial = d.Wrap
		}
		return o, nil
	}
	conn, err := d.Dial(ctx)
	if err != nil {
		_ = o.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	RememberAddrs(g, conn)
	if d.RememberTLS {
		RememberTLSPeer(g, conn)
	}
	if d.LogOK && g != nil && g.Log != nil {
		g.Log.Infof("successfully connected from %s to %s%s", conn.LocalAddr(), conn.RemoteAddr(), d.LogSuffix)
	}
	wrap := d.Wrap
	if wrap == nil {
		wrap = func(c net.Conn) (relay.Stream, error) {
			return WrapCommon(s, relay.NetStream{Conn: c})
		}
	}
	st, err := wrap(conn)
	if err != nil {
		_ = conn.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		_ = o.Close()    // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	o.Stream = st
	return o, nil
}
