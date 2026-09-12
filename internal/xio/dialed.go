package xio

import (
	"context"
	"net"

	"github.com/oittaa/socat/internal/addrconfig"
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
	runCleanup := func() {
		for _, f := range d.Cleanup {
			if f != nil {
				f()
			}
		}
	}
	fork, maxChildren, err := ForkLimits(s)
	if err != nil {
		runCleanup()
		return nil, err
	}
	wrap := d.Wrap
	if wrap == nil {
		wrap = DefaultWrapDial(s)
	}
	attach := func(o *Opened) *Opened {
		for _, f := range d.Cleanup {
			if f != nil {
				o.AddCleanup(f)
			}
		}
		return o
	}
	if fork {
		return attach(NewRepeatedDial(d.Label, RepeatedDial{
			Dial:        WrapNetNSDial(netNamespaceName(s), g, d.Dial),
			Interval:    s.Common.Retry.Policy().Interval,
			MaxChildren: maxChildren,
			WrapDial:    wrap,
		})), nil
	}
	conn, err := d.Dial(ctx)
	if err != nil {
		runCleanup()
		return nil, err
	}
	RememberAddrs(g, conn)
	if d.RememberTLS {
		if err := RememberTLSPeer(g, conn, HandshakeTimeout(s)); err != nil {
			logx.CloseQuiet(conn)
			runCleanup()
			return nil, err
		}
	}
	if d.LogOK && g != nil && g.Log != nil {
		g.Log.Infof("successfully connected from %s to %s%s", conn.LocalAddr(), conn.RemoteAddr(), d.LogSuffix)
	}
	st, err := wrap(conn)
	if err != nil {
		logx.CloseQuiet(conn)
		runCleanup()
		return nil, err
	}
	return attach(NewReady(d.Label, st)), nil
}
