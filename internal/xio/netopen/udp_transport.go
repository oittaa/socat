package netopen

import (
	"context"
	"net"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func listenPacketForSpec(ctx context.Context, network, address string, s parse.Spec) (net.PacketConn, error) {
	laddr, err := xio.ResolveUDPAddr(ctx, s, network, address)
	if err != nil {
		return nil, err
	}
	lc := udpListenConfig(s)
	return lc.ListenPacket(ctx, network, laddr.String())
}

func dialUDPForSpec(req dialRequest, laddr net.Addr, remote string) (net.Conn, error) {
	if host, port, err := net.SplitHostPort(remote); err == nil {
		stripped := xio.StripBrackets(host)
		netw, ip, resolveErr := xio.LookupDialIP(req.ctx, req.spec, req.network, stripped)
		if resolveErr != nil {
			return nil, resolveErr
		}
		if ip != nil && net.ParseIP(stripped) == nil {
			req.network = netw
			remote = net.JoinHostPort(xio.FormatIPForNetwork(req.network, ip), port)
		}
	}
	matched, err := xio.MatchLocalPacketAddr(req.network, laddr)
	if err != nil {
		return nil, err
	}
	config, cfgErr := xio.OpeningConfig(req.ctx, req.spec)
	if cfgErr != nil {
		return nil, cfgErr
	}
	d := net.Dialer{
		Timeout:   req.timeout,
		LocalAddr: matched,
		Control:   xio.DialControl(req.spec, req.network, req.control),
		// UDP connect still carries a resolver so a leftover hostname (or
		// Dialer internals) cannot fall back to DefaultResolver.
		Resolver: xio.LookupResolver(config),
	}
	return d.DialContext(req.ctx, req.network, remote)
}
