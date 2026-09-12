package netopen

import (
	"context"
	"fmt"
	"github.com/oittaa/socat/internal/addrconfig"
	"net"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/relay"
)

func openUDPConnect(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPConnectNetwork(ctx, s, mode, g, NetworkUDP(g.Options(), s, "udp4"))
}
func openUDP4Connect(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPConnectNetwork(ctx, s, mode, g, "udp4")
}
func openUDP6Connect(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPConnectNetwork(ctx, s, mode, g, "udp6")
}

func openUDPConnectNetwork(ctx context.Context, s addrconfig.Address, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	if !s.Network.TargetSet {
		return nil, fmt.Errorf("%s requires host and port", s.Type)
	}
	host := s.Network.Target
	port := s.Network.TargetPort
	if host.Empty() || port.Empty() {
		return nil, fmt.Errorf("%s: invalid host/port", s.Type)
	}
	// Select the mapped remote network before resolving bind=. UDP6 to an
	// A-only hostname with ai-v4mapped switches udp6→udp4; resolving
	// bind=<A-only-host> on udp6 first fails with "no suitable address".
	if !host.IsLiteral() {
		netw, netErr := xio.PacketNetworkForHost(ctx, s, network, host)
		if netErr != nil {
			return nil, netErr
		}
		network = netw
	}
	raddr, err := xio.ResolveUDPTarget(ctx, s, network, host, port)
	if err != nil {
		return nil, err
	}
	lowport := xio.ClientUsesLowport(s)
	var conn net.Conn
	if lowport {
		bind, bindErr := xio.ListenBindHost(s, network)
		if bindErr != nil {
			return nil, bindErr
		}
		conn, err = dialUDPLowport(ctx, network, bind, raddr, s, g)
	} else {
		var laddr net.Addr
		if s.Network.BindSet || s.Network.SourcePortSet || s.Network.BindPortSet {
			bind, bindErr := xio.ListenBindHost(s, network)
			if bindErr != nil {
				return nil, bindErr
			}
			laddr, err = xio.ResolveUDPTarget(ctx, s, network, bind, xio.ClientLocalPort(s))
			if err != nil {
				return nil, err
			}
		}
		conn, err = dialUDPForSpec(dialRequest{
			ctx:     ctx,
			network: network,
			timeout: xio.ConnectTimeout(s),
			config:  s,
		}, laddr, raddr)
	}
	if err != nil {
		return nil, err
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		logx.CloseQuiet(conn)
		return nil, fmt.Errorf("UDP: unexpected connection type %T", conn)
	}
	if err := xio.ApplyUDPConnOpts(udpConn, s, network); err != nil {
		logx.CloseQuiet(conn)
		return nil, err
	}
	st := relay.Stream(udpConnectStream{NetStream: relay.NetStream{Conn: xio.WrapUDPAncillary(udpConn, s, g)}})
	st, err = xio.WrapOpened(s, st)
	if err != nil {
		logx.CloseQuiet(conn)
		return nil, err
	}
	return xio.NewReady("UDP:"+raddr.String(), st)
}

func dialUDPLowport(ctx context.Context, network string, bind addrconfig.HostTarget, remote *net.UDPAddr, s addrconfig.Address, g *xio.Global) (net.Conn, error) {
	var conn net.Conn
	_, err := xio.FirstAvailableLowport(func(port int) error {
		if g != nil && g.Log != nil {
			g.Log.Debugf("bind(%s:%d)", bind.Original(), port)
		}
		laddr, err := xio.ResolveUDPTarget(ctx, s, network, bind, addrconfig.PortFromText(fmt.Sprintf("%d", port)))
		if err != nil {
			return err
		}
		conn, err = dialUDPForSpec(dialRequest{
			ctx:     ctx,
			network: network,
			timeout: xio.ConnectTimeout(s),
			config:  s,
			g:       g,
		}, laddr, remote)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("lowport: cannot bind a port in %d-%d: %w", xio.LowportMin, xio.LowportMax, err)
	}
	return conn, nil
}

func NetworkUDP(opts xio.Options, s addrconfig.Address, def string) string {
	if s.Network.ProtocolSet {
		if n := xio.NetworkFromIPFamily(s.Network.IPFamily, "udp"); n != "" {
			return n
		}
	}
	ver := opts.IPVersion
	switch ver {
	case xio.IPv4:
		return "udp4"
	case xio.IPv6:
		return "udp6"
	case xio.IPvAny:
		return "udp"
	default:
		return def
	}
}

func udpNetworkWithListenDefault(opts xio.Options, s addrconfig.Address) string {
	return xio.TCPToUDPNetwork(xio.ListenNetwork(opts, s))
}

// udpConnectStream is UDP/UDP4/UDP6 CONNECT (and UDP-LISTEN,fork sessions).
// Unspecified shut policy is shut-null: ShutdownWrite sends one zero-length
// datagram. A successful zero-length Read is EOF so that packet ends the
// peer transfer. Explicit shut-* options still wrap this stream.
type udpConnectStream struct {
	relay.NetStream
}

func (s udpConnectStream) Read(p []byte) (int, error) {
	n, err := s.NetStream.Read(p)
	return xio.ZeroLengthMessageEOF(n, err, len(p))
}

func (s udpConnectStream) ShutdownWrite() error {
	_, _ = s.Write(nil)
	return nil
}

func (s udpConnectStream) NetConn() net.Conn { return s.Conn }

func (s udpConnectStream) UnwrapStream() relay.Stream { return s.NetStream }
