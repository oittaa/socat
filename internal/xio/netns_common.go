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
// Classic baseline: tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba
// xio-ip.c opt_res_nsaddr/xio_res_init; official master
// af5388c898c7bb60997935aee93c223deba60c4a is unchanged. Classic temporarily
// replaces process-global _res.nsaddr_list[0] and other _res fields. This
// security-related port difference uses a per-address resolver and never
// mutates net.DefaultResolver or libc _res. Remaining libc res-* flags
// (debug, search, retry, retrans, …) are rejected rather than applied
// globally; res-usevc is implemented here via Resolver.Dial (`=0` restores
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
				// Classic TYPE_IP4SOCK resolves the nameserver with AF_INET
				// (xioopts.c / xioresolve at tag-1.8.1.3
				// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
				// af5388c898c7bb60997935aee93c223deba60c4a). Dual-stack
				// "udp"/"tcp" would let res-nsaddr=localhost prefer ::1.
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
