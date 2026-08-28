package netopen

import (
	"context"
	"net"
	"syscall"
	"time"

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

func dialUDPForSpec(ctx context.Context, network string, laddr net.Addr, remote string, s parse.Spec, extra func(string, string, syscall.RawConn) error, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{
		Timeout:   timeout,
		LocalAddr: laddr,
		Control:   xio.DialControl(s, network, extra),
		// UDP connect passes hostname:port to DialContext. Without this,
		// net.Dialer uses DefaultResolver and ignores res-nsaddr.
		Resolver: xio.LookupResolver(s),
	}
	return d.DialContext(ctx, network, remote)
}
