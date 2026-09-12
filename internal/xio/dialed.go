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

func runDialedCleanup(fns []func()) {
	for i := len(fns) - 1; i >= 0; i-- {
		if fns[i] != nil {
			fns[i]()
		}
	}
}

func attachDialedCleanup(o *Opened, fns []func()) *Opened {
	for _, f := range fns {
		if f != nil {
			o.AddCleanup(f)
		}
	}
	return o
}

// OpenDialed opens a client address: CONNECT,fork loop, or one dial + wrap.
func OpenDialed(ctx context.Context, s addrconfig.Address, g *Global, d Dialed) (*Opened, error) {
	fail := func(err error) (*Opened, error) {
		runDialedCleanup(d.Cleanup)
		return nil, err
	}
	fork, maxChildren, err := ForkLimits(s)
	if err != nil {
		return fail(err)
	}
	wrap := d.Wrap
	if wrap == nil {
		wrap = DefaultWrapDial(s)
	}
	if fork {
		o, err := NewRepeatedDial(d.Label, RepeatedDial{
			Dial:        WrapNetNSDial(netNamespaceName(s), g, d.Dial),
			Interval:    s.Common.Retry.Policy().Interval,
			MaxChildren: maxChildren,
			WrapDial:    wrap,
		})
		if err != nil {
			return fail(err)
		}
		return attachDialedCleanup(o, d.Cleanup), nil
	}
	conn, err := d.Dial(ctx)
	if err != nil {
		return fail(err)
	}
	RememberAddrs(g, conn)
	if d.RememberTLS {
		if err := RememberTLSPeer(g, conn, HandshakeTimeout(s)); err != nil {
			logx.CloseQuiet(conn)
			return fail(err)
		}
	}
	if d.LogOK && g != nil && g.Log != nil {
		g.Log.Infof("successfully connected from %s to %s%s", conn.LocalAddr(), conn.RemoteAddr(), d.LogSuffix)
	}
	st, err := wrap(conn)
	if err != nil {
		logx.CloseQuiet(conn)
		return fail(err)
	}
	o, err := NewReady(d.Label, st)
	if err != nil {
		if st != nil {
			logx.CloseQuiet(st)
		} else {
			logx.CloseQuiet(conn)
		}
		return fail(err)
	}
	return attachDialedCleanup(o, d.Cleanup), nil
}
