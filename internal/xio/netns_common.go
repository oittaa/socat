package xio

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

func netnsName(s parse.Spec) (string, bool) {
	if !s.HasOption("netns") {
		return "", false
	}
	name := s.OptionValue("netns", "")
	if name == "" {
		return "", false
	}
	return name, true
}

func warnNetNSExperimental(g *Global) {
	if g != nil && g.Experimental {
		return
	}
	if g != nil && g.Log != nil {
		g.Log.Warningf("option \"netns\" is experimental")
	}
}

// LookupResolver returns the resolver scoped to one address. With netns= it
// uses Go DNS so sockets are created after LockOSThread+setns.
//
// Security-related difference: a per-address resolver, never mutating
// net.DefaultResolver or libc _res. Remaining libc res-* flags (debug,
// search, retry, retrans, …) are rejected rather than applied globally;
// res-usevc is implemented here via Resolver.Dial (`=0` restores
// UDP-then-TCP, including when resolv.conf has use-vc).
func LookupResolver(s parse.Spec) *net.Resolver {
	r := lookupResolverBase(s)
	if !s.HasOption("res-usevc") {
		return r
	}
	return resolverRewriteDNSTransport(r, s.BoolOption("res-usevc"))
}

func lookupResolverBase(s parse.Spec) *net.Resolver {
	if s.HasOption("res-nsaddr") {
		nsAddr, err := ParseResNSAddr(s.OptionValue("res-nsaddr", ""))
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
				c, err := d.DialContext(ctx, network, nsAddr)
				if err != nil {
					return nil, err
				}
				return closeConnWhenDone(ctx, c), nil
			},
		}
	}
	if _, ok := netnsName(s); ok {
		return &net.Resolver{PreferGo: true}
	}
	return net.DefaultResolver
}

// WrapNetNSDial runs dial inside WithNetNS so CONNECT,fork reconnects stay in
// the target namespace (OpenDialed does not dial during OpenSpec).
func WrapNetNSDial(s parse.Spec, g *Global, dial func(context.Context) (net.Conn, error)) func(context.Context) (net.Conn, error) {
	if dial == nil {
		return nil
	}
	if _, ok := netnsName(s); !ok {
		return dial
	}
	return func(ctx context.Context) (net.Conn, error) {
		var c net.Conn
		err := WithNetNS(s, g, func() error {
			var e error
			c, e = dial(ctx)
			return e
		})
		return c, err
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
