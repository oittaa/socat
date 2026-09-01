package netopen

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func openTCPConnect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	host := ""
	if len(s.Params) >= 1 {
		host = s.Params[0]
	}
	// Generic TCP: dual-stack resolve; -4/-6 only reorder preference.
	return openTCPConnectNetwork(ctx, s, mode, g, xio.ConnectNetworkForType(g, s, host, "tcp"))
}

func openTCP4Connect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openTCPConnectNetwork(ctx, s, mode, g, "tcp4")
}

func openTCP6Connect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openTCPConnectNetwork(ctx, s, mode, g, "tcp6")
}

func openTCPConnectNetwork(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	host, port, err := xio.HostPortParams(s)
	if err != nil {
		return nil, err
	}
	if host == "" || port == "" {
		return nil, fmt.Errorf("%s: invalid host/port", s.Type)
	}
	// Honour pf= even when called from TCP4/TCP6 openers.
	network = xio.ConnectNetworkForType(g, s, host, network)
	addr := net.JoinHostPort(xio.StripBrackets(host), port)

	timeout := xio.ConnectTimeout(s)

	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		err := xio.WithRetry(dctx, s, g, network+" connect", func() error {
			c, e := xio.DialTCPAll(dctx, network, xio.StripBrackets(host), port, s, g, timeout, nil)
			if e != nil {
				return e
			}
			conn = c
			return nil
		})
		return conn, err
	}

	return xio.OpenDialed(ctx, s, g, xio.Dialed{
		Label: fmt.Sprintf("%s:%s", network, addr),
		Dial:  dialOnce,
		LogOK: true,
		Wrap: func(c net.Conn) (relay.Stream, error) {
			return xio.WrapCommonAfterConnected(s, relay.NetStream{Conn: c})
		},
	})
}

func openTCPListen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	// Listen address family:
	//   1) address option pf=
	//   2) explicit -4 / -6 / -0
	//   3) env SOCAT_DEFAULT_LISTEN_IP
	//   4) default IPv4
	netw := xio.ListenNetwork(g, s)
	return openTCPListenNetwork(ctx, s, mode, g, netw)
}

func openTCP4Listen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openTCPListenNetwork(ctx, s, mode, g, "tcp4")
}

func openTCP6Listen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	// Go's "tcp6" forces IPV6_V6ONLY=1 after our Control hook. For
	// ipv6-v6only=0 use dual-stack "tcp" on :: so IPv4 clients work.
	netw := "tcp6"
	if s.HasOption("ipv6-v6only") && !s.BoolOption("ipv6-v6only") {
		netw = "tcp"
	}
	return openTCPListenNetwork(ctx, s, mode, g, netw)
}

func openTCPListenNetwork(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("%s requires port", s.Type)
	}
	port := s.Params[0]
	// Reject non-numeric/service empties used by test.sh probes (TYPE:::::)
	if port == "" || strings.Trim(port, ":") == "" {
		return nil, fmt.Errorf("%s: invalid port %q", s.Type, port)
	}
	host, err := xio.ListenBindHost(s, network, s.OptionValue("bind", ""))
	if err != nil {
		return nil, err
	}
	host, err = xio.ResolveIPHost(ctx, s, network, host)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(xio.StripBrackets(host), port)

	lc := xio.NewTCPListenConfig(s)
	ln, err := xio.ListenStream(ctx, lc, network, addr, s)
	if err != nil {
		return nil, err
	}

	return xio.OpenListenSession(ctx, s, g, xio.ListenSession{
		Listener: ln,
		Label:    fmt.Sprintf("%s-LISTEN:%s", network, port),
		WrapDial: func(c net.Conn) (relay.Stream, error) {
			return xio.WrapAccepted(s, c, func(c net.Conn) error {
				return xio.ApplyTCPConnOpts(s, c)
			})
		},
	})
}
