package dtlsopen

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/oittaa/socat/internal/dtls13"
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
)

func wrap(s parse.Spec) func(net.Conn) (relay.Stream, error) {
	return func(c net.Conn) (relay.Stream, error) {
		dc, ok := c.(datagramConn)
		if !ok {
			return nil, fmt.Errorf("DTLS connection lacks datagram operations")
		}
		return xio.WrapStream(s, relay.NetStream{Conn: &streamConn{datagramConn: dc}}, xio.StreamSocketTimeouts)
	}
}

func openClient(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
	host, port, err := xio.HostPortParams(s)
	if err != nil {
		return nil, err
	}
	if host == "" || port == "" {
		return nil, fmt.Errorf("%s requires host and port", s.Type)
	}
	cfg, err := endpointConfig(s, host, false)
	if err != nil {
		return nil, err
	}
	dest := net.JoinHostPort(xio.StripBrackets(host), port)
	network := xio.TCPToUDPNetwork(xio.ConnectNetworkForType(g, s, host, "tcp"))
	dial := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		err := xio.WithRetry(dctx, s, g, s.Type, func() error {
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
			peer, err := xio.ResolveUDPAddr(cctx, s, netw, dest)
			if err != nil {
				return err
			}
			bind, err := xio.ListenBindHost(s, netw, s.OptionValue("bind", ""))
			if err != nil {
				return err
			}
			pc, err := xio.ListenClientPacket(cctx, netw, bind, s.OptionValue("sourceport", ""), s, g)
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
		Label: s.Type + ":" + dest, Dial: dial, Wrap: wrap(s),
		RememberTLS: true, LogOK: true, LogSuffix: " (DTLS)",
	})
}

func openServer(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
	if len(s.Params) == 0 || s.Params[0] == "" {
		return nil, fmt.Errorf("%s requires port", s.Type)
	}
	cfg, err := endpointConfig(s, "", true)
	if err != nil {
		return nil, err
	}
	filter, err := xio.NewPeerFilter(ctx, s, g)
	if err != nil {
		return nil, err
	}
	network := xio.TCPToUDPNetwork(xio.ListenNetwork(g, s))
	if network == "udp6" && s.HasOption("ipv6-v6only") && !s.BoolOption("ipv6-v6only") {
		network = "udp"
	}
	host, err := xio.ListenBindHost(s, network, s.OptionValue("bind", ""))
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(xio.StripBrackets(host), s.Params[0])
	pc, err := xio.ListenPacketWithOptions(ctx, network, addr, s)
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
		Label: s.Type + ":" + s.Params[0], WrapDial: wrap(s), PeerFilter: filter,
		Accept: ln.AcceptContext, UseContextTimeout: true, KeepListenerForSession: true,
		ListeningLog: fmt.Sprintf("listening on %s (DTLS)", ln.Addr()),
		AfterAccept:  func(g *xio.Global, c net.Conn) error { return xio.RememberTLSPeer(g, c, 0) },
	})
}

// An accept timeout leaves accepted sessions alive until endpoint cleanup.
type drainingListener struct{ *dtls13.Listener }

func (l drainingListener) Close() error { return l.StopAccept() }
