package dtlsopen

import (
	"context"
	"fmt"
	"github.com/oittaa/socat/internal/addrconfig"
	"net"
	"net/netip"

	"github.com/oittaa/socat/internal/dtls13"
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
)

func wrap(s addrconfig.Address) func(net.Conn) (relay.Stream, error) {
	return func(c net.Conn) (relay.Stream, error) {
		dc, ok := c.(datagramConn)
		if !ok {
			return nil, fmt.Errorf("DTLS connection lacks datagram operations")
		}
		return xio.WrapStream(s, relay.NetStream{Conn: &streamConn{datagramConn: dc}}, xio.StreamSocketTimeouts)
	}
}

func openClient(ctx context.Context, s addrconfig.Address, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if !s.Network.TargetSet {
		return nil, fmt.Errorf("%s requires host and port", s.Type)
	}
	host := s.Network.Target
	port := s.Network.TargetPort
	if host.Empty() || port.Empty() {
		return nil, fmt.Errorf("%s requires host and port", s.Type)
	}
	cfg, err := endpointConfig(ctx, s, host.String(), false)
	if err != nil {
		return nil, err
	}
	network := xio.TCPToUDPNetwork(xio.ConnectNetworkForType(g, s, host, "tcp"))
	dial := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		err := xio.WithRetry(dctx, g, s.Common.Retry.Policy(), s.Type, func() error {
			cctx := dctx
			if timeout := xio.CombinedConnectHandshakeTimeout(s); timeout > 0 {
				var cancel context.CancelFunc
				cctx, cancel = context.WithTimeout(cctx, timeout)
				defer cancel()
			}
			netw, err := xio.PacketNetworkForHost(cctx, s, network, host)
			if err != nil {
				return err
			}
			peer, err := xio.ResolveUDPTarget(cctx, s, netw, host, port)
			if err != nil {
				return err
			}
			bind, err := xio.ListenBindHost(s, netw)
			if err != nil {
				return err
			}
			pc, err := xio.ListenClientPacket(cctx, netw, bind, xio.ClientLocalPort(s), s, g)
			if err != nil {
				return err
			}
			conn, err = dtls13.Client(cctx, pc, peer, cfg)
			if err != nil {
				logx.CloseQuiet(pc)
			}
			return err
		})
		return conn, err
	}
	return xio.OpenDialed(ctx, s, g, xio.Dialed{
		Label: s.Type + ":" + net.JoinHostPort(host.String(), port.Text()), Dial: dial, Wrap: wrap(s),
		RememberTLS: true, LogOK: true, LogSuffix: " (DTLS)",
	})
}

func openServer(ctx context.Context, s addrconfig.Address, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
	port, err := xio.ListenPort(s)
	if err != nil {
		return nil, err
	}
	cfg, err := endpointConfig(ctx, s, "", true)
	if err != nil {
		return nil, err
	}
	filter, err := xio.PreparedPeerFilter(ctx, s, g)
	if err != nil {
		return nil, err
	}
	network := xio.TCPToUDPNetwork(xio.ListenNetwork(g, s))
	network = xio.DualStackListenNetwork(s, network)
	host, err := xio.ListenBindHost(s, network)
	if err != nil {
		return nil, err
	}
	pc, err := xio.ListenPacketWithOptions(ctx, network, host, port, s)
	if err != nil {
		return nil, err
	}
	cfg.AcceptPeer = func(peer netip.AddrPort) bool {
		return filter.AllowAddr(net.UDPAddrFromAddrPort(peer), pc.LocalAddr()) == nil
	}
	ln, err := dtls13.Listen(pc, cfg)
	if err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}
	return xio.OpenListenSession(ctx, s, g, xio.ListenSession{
		Listener: drainingListener{ln}, CloseListener: ln.Close,
		Label: s.Type + ":" + port.Text(), WrapDial: wrap(s), PeerFilter: filter,
		KeepListenerForSession: true,
		ListeningLog:           fmt.Sprintf("listening on %s (DTLS)", ln.Addr()),
		AfterAccept:            func(g *xio.Global, c net.Conn) error { return xio.RememberTLSPeer(g, c, 0) },
	})
}

// An accept timeout leaves accepted sessions alive until endpoint cleanup.
type drainingListener struct{ *dtls13.Listener }

func (l drainingListener) Close() error { return l.StopAccept() }
