package netopen

import (
	"context"
	"fmt"
	"github.com/oittaa/socat/internal/addrconfig"
	"net"

	"github.com/oittaa/socat/internal/xio"
)

// SCTP (RFC 9260) one-to-one style: SOCK_STREAM + IPPROTO_SCTP.
// The kernel implements the association (INIT/COOKIE four-way, SACK, SHUTDOWN).
// We do not implement the packet format in userspace. The Linux wrappers
// github.com/ishidawataru/sctp and github.com/georgeyanev/go-sctp use the
// same kernel sockets; we stay on unix.Socket + our listen/connect path.

func openSCTPConnect(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSCTPConnectNetwork(ctx, s, mode, g, sctpNetwork(xio.ConnectNetworkForType(g, s, xio.FirstHost(s), "tcp")))
}

func openSCTP4Connect(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSCTPConnectNetwork(ctx, s, mode, g, "sctp4")
}

func openSCTP6Connect(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSCTPConnectNetwork(ctx, s, mode, g, "sctp6")
}

func openSCTPConnectNetwork(ctx context.Context, s addrconfig.Address, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	if !s.Network.TargetSet {
		return nil, fmt.Errorf("%s requires host and port", s.Type)
	}
	host, port := s.Network.Target, s.Network.TargetPort
	if host.String() == "" || port.Text() == "" {
		return nil, fmt.Errorf("%s: invalid host/port", s.Type)
	}
	network = sctpNetwork(xio.ConnectNetworkForType(g, s, host, tcpNetwork(network)))
	addr := net.JoinHostPort(xio.StripBrackets(host.String()), port.Text())
	timeout := xio.ConnectTimeout(s)

	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		err := xio.WithRetry(dctx, g, network+" connect", func() error {
			c, e := dialSCTPAll(dctx, xio.DialTarget{Network: network, Host: host, Port: port}, s, g, timeout, nil)
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

func openSCTPListen(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSCTPListenNetwork(ctx, s, mode, g, sctpNetwork(xio.ListenNetwork(g, s)))
}

func openSCTP4Listen(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSCTPListenNetwork(ctx, s, mode, g, "sctp4")
}

func openSCTP6Listen(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSCTPListenNetwork(ctx, s, mode, g, xio.DualStackListenNetwork(s, "sctp6"))
}

func openSCTPListenNetwork(ctx context.Context, s addrconfig.Address, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	port, err := xio.ListenPort(s)
	if err != nil {
		return nil, err
	}
	host, err := xio.ListenBindHost(s, network)
	if err != nil {
		return nil, err
	}
	ip, err := xio.ResolveIPTarget(ctx, s, network, host)
	if err != nil {
		return nil, err
	}
	ln, err := listenSCTP(ctx, network, ip, port, s)
	if err != nil {
		return nil, err
	}

	return xio.OpenListenSession(ctx, s, g, xio.ListenSession{
		Listener: ln,
		Label:    fmt.Sprintf("%s-LISTEN:%s", network, port.Text()),
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
