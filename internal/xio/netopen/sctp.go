package netopen

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

// SCTP (RFC 9260) one-to-one style: SOCK_STREAM + IPPROTO_SCTP.
// The kernel implements the association (INIT/COOKIE four-way, SACK, SHUTDOWN).
// We do not implement the packet format in userspace. The Linux wrappers
// github.com/ishidawataru/sctp and github.com/georgeyanev/go-sctp use the
// same kernel sockets; we stay on unix.Socket + our listen/connect path.

func openSCTPConnect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	host := ""
	if len(s.Params) >= 1 {
		host = s.Params[0]
	}
	return openSCTPConnectNetwork(ctx, s, mode, g, sctpNetwork(xio.ConnectNetworkForType(g, s, host, "tcp")))
}

func openSCTP4Connect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSCTPConnectNetwork(ctx, s, mode, g, "sctp4")
}

func openSCTP6Connect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSCTPConnectNetwork(ctx, s, mode, g, "sctp6")
}

func openSCTPConnectNetwork(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	host, port, err := xio.HostPortParams(s)
	if err != nil {
		return nil, err
	}
	if host == "" || port == "" {
		return nil, fmt.Errorf("%s: invalid host/port", s.Type)
	}
	network = sctpNetwork(xio.ConnectNetworkForType(g, s, host, tcpNetwork(network)))
	addr := net.JoinHostPort(xio.StripBrackets(host), port)
	timeout := xio.ConnectTimeout(s)

	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		err := xio.WithRetry(dctx, s, g, network+" connect", func() error {
			c, e := dialSCTPAll(dctx, network, xio.StripBrackets(host), port, s, g, timeout, nil)
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
	})
}

func openSCTPListen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSCTPListenNetwork(ctx, s, mode, g, sctpNetwork(xio.ListenNetwork(g, s)))
}

func openSCTP4Listen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSCTPListenNetwork(ctx, s, mode, g, "sctp4")
}

func openSCTP6Listen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	netw := "sctp6"
	if s.HasOption("ipv6-v6only") && !s.BoolOption("ipv6-v6only") {
		netw = "sctp"
	}
	return openSCTPListenNetwork(ctx, s, mode, g, netw)
}

func openSCTPListenNetwork(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("%s requires port", s.Type)
	}
	port := s.Params[0]
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
	ln, err := listenSCTP(ctx, network, host, port, s)
	if err != nil {
		return nil, err
	}

	return xio.OpenListenSession(ctx, s, g, xio.ListenSession{
		Listener: ln,
		Label:    fmt.Sprintf("%s-LISTEN:%s", network, port),
	})
}

func sctpNetwork(tcpNet string) string {
	switch tcpNet {
	case "tcp6":
		return "sctp6"
	case "tcp":
		return "sctp"
	default:
		return "sctp4"
	}
}

func tcpNetwork(sctpNet string) string {
	switch sctpNet {
	case "sctp6":
		return "tcp6"
	case "sctp":
		return "tcp"
	default:
		return "tcp4"
	}
}
