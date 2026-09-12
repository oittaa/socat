package netopen

import (
	"context"
	"fmt"
	"github.com/oittaa/socat/internal/addrconfig"
	"net"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/relay"
)

func openTCPConnect(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openTCPConnectNetwork(ctx, s, mode, g, xio.ConnectNetworkForType(g, s, xio.FirstHost(s), "tcp"))
}

func openTCP4Connect(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openTCPConnectNetwork(ctx, s, mode, g, "tcp4")
}

func openTCP6Connect(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openTCPConnectNetwork(ctx, s, mode, g, "tcp6")
}

func openTCPConnectNetwork(ctx context.Context, s addrconfig.Address, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	if !s.Network.TargetSet {
		return nil, fmt.Errorf("%s requires host and port", s.Type)
	}
	host, port := s.Network.Target, s.Network.TargetPort
	if host.Empty() || port.Empty() {
		return nil, fmt.Errorf("%s: invalid host/port", s.Type)
	}
	// Honour pf= even when called from TCP4/TCP6 openers.
	network = xio.ConnectNetworkForType(g, s, host, network)
	addr := net.JoinHostPort(xio.StripBrackets(host.String()), port.Text())

	timeout := xio.ConnectTimeout(s)

	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		err := xio.WithRetry(dctx, g, network+" connect", func() error {
			c, e := xio.DialTCPAll(dctx, xio.DialTarget{Network: network, Host: host, Port: port}, s, g, timeout, nil)
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
			return xio.SetupConnectedStream(s, relay.NetStream{Conn: c})
		},
	})
}

func openTCPListen(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	// Listen address family:
	//   1) address option pf=
	//   2) explicit -4 / -6 / -0
	//   3) env SOCAT_DEFAULT_LISTEN_IP
	//   4) default IPv4
	netw := xio.ListenNetwork(g, s)
	return openTCPListenNetwork(ctx, s, mode, g, netw)
}

func openTCP4Listen(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openTCPListenNetwork(ctx, s, mode, g, "tcp4")
}

func openTCP6Listen(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	// Go's "tcp6" forces IPV6_V6ONLY=1 after our Control hook. For
	// ipv6-v6only=0 use dual-stack "tcp" on :: so IPv4 clients work.
	return openTCPListenNetwork(ctx, s, mode, g, xio.DualStackListenNetwork(s, "tcp6"))
}

func openTCPListenNetwork(ctx context.Context, s addrconfig.Address, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	port, err := xio.ListenPort(s)
	if err != nil {
		return nil, err
	}
	addr, err := xio.TCPListenAddress(ctx, s, network, port)
	if err != nil {
		return nil, err
	}

	ln, err := xio.ListenTCP(ctx, s, network, addr)
	if err != nil {
		return nil, err
	}

	return xio.OpenListenSession(ctx, s, g, xio.ListenSession{
		Listener: ln,
		Label:    fmt.Sprintf("%s-LISTEN:%s", network, port.Text()),
		WrapDial: func(c net.Conn) (relay.Stream, error) {
			if err := xio.ApplyTCPConnOpts(s, c); err != nil {
				return nil, err
			}
			return xio.SetupConnectedStream(s, relay.NetStream{Conn: c})
		},
	})
}
