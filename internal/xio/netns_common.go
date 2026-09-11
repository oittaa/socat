package xio

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/oittaa/socat/internal/addrconfig"
)

func netNamespaceName(config addrconfig.Address) string {
	return config.Common.NetNamespace.Value
}

func warnNetNSExperimental(g *Global) {
	if g != nil && g.Experimental {
		return
	}
	if g != nil && g.Log != nil {
		g.Log.Warningf("option \"netns\" is experimental")
	}
}

// LookupResolver returns the resolver scoped to one prepared address. It never
// mutates net.DefaultResolver or libc _res. Remaining libc res-* flags
// (debug, search, retry, retrans, …) are rejected rather than applied
// globally. Construction is: select the base (system default, res-nsaddr,
// or PreferGo for netns), apply res-usevc transport policy, then wrap
// custom Dial connections once so session cancel unblocks in-flight
// DNS reads.
func LookupResolver(config addrconfig.Address) *net.Resolver {
	r := lookupResolverBase(config)
	if config.Common.UseVC.Set {
		r = resolverRewriteDNSTransport(r, config.Common.UseVC.Value)
	}
	return wrapDNSDialCloseWhenDone(r)
}

func lookupResolverBase(config addrconfig.Address) *net.Resolver {
	if config.Common.NameServer.Set {
		nsAddr, err := addrconfig.ParseResNSAddr(config.Common.NameServer.Value)
		if err != nil {
			return &net.Resolver{
				PreferGo: true,
				Dial: func(context.Context, string, string) (net.Conn, error) {
					return nil, err
				},
			}
		}
		return &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				// res-nsaddr resolves the nameserver as IPv4 so
				// res-nsaddr=localhost does not prefer ::1.
				switch {
				case strings.HasPrefix(network, "udp"):
					network = "udp4"
				case strings.HasPrefix(network, "tcp"):
					network = "tcp4"
				default:
					return nil, fmt.Errorf("res-nsaddr: unsupported DNS transport %q", network)
				}
				var d net.Dialer
				return d.DialContext(ctx, network, nsAddr)
			},
		}
	}
	if netNamespaceName(config) != "" {
		return &net.Resolver{PreferGo: true}
	}
	return net.DefaultResolver
}

// WrapNetNSDial runs dial inside WithNetNS so CONNECT,fork reconnects stay in
// the target namespace (OpenDialed does not dial during OpenSpec).
func WrapNetNSDial(name string, g *Global, dial func(context.Context) (net.Conn, error)) func(context.Context) (net.Conn, error) {
	if dial == nil {
		return nil
	}
	if name == "" {
		return dial
	}
	return func(ctx context.Context) (net.Conn, error) {
		var c net.Conn
		err := WithNetNS(name, g, func() error {
			var e error
			c, e = dial(ctx)
			return e
		})
		return c, err
	}
}

func wrapDNSDialCloseWhenDone(r *net.Resolver) *net.Resolver {
	if r == nil || r == net.DefaultResolver {
		return r
	}
	inner := r.Dial
	return &net.Resolver{
		PreferGo:     true,
		StrictErrors: r.StrictErrors,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var c net.Conn
			var err error
			if inner != nil {
				c, err = inner(ctx, network, address)
			} else {
				var d net.Dialer
				c, err = d.DialContext(ctx, network, address)
			}
			if err != nil {
				return nil, err
			}
			return closeConnWhenDone(ctx, c), nil
		},
	}
}

// closeConnWhenDone closes c when ctx is done so a blocking DNS Read returns.
// LookupAddr does not watch ctx.Done() after Dial; LookupIP does.
func closeConnWhenDone(ctx context.Context, c net.Conn) net.Conn {
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	cc := &cancelConn{Conn: c, stop: stop}
	if _, ok := c.(net.PacketConn); ok {
		return &cancelPacketConn{cancelConn: cc}
	}
	return cc
}

type cancelConn struct {
	net.Conn
	stop func() bool
}

func (c *cancelConn) NetConn() net.Conn { return c.Conn }

func (c *cancelConn) Close() error {
	c.stop()
	return c.Conn.Close()
}

// cancelPacketConn keeps the PacketConn type so Go DNS uses UDP framing.
type cancelPacketConn struct {
	*cancelConn
}

func (c *cancelPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return c.Conn.(net.PacketConn).ReadFrom(p)
}

func (c *cancelPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.Conn.(net.PacketConn).WriteTo(p, addr)
}

var (
	_ net.Conn       = (*cancelConn)(nil)
	_ net.Conn       = (*cancelPacketConn)(nil)
	_ net.PacketConn = (*cancelPacketConn)(nil)
)
