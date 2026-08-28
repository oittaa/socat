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
	lc := udpListenConfig(s)
	return lc.ListenPacket(ctx, network, address)
}

func dialUDPForSpec(ctx context.Context, network string, laddr net.Addr, remote string, s parse.Spec, extra func(string, string, syscall.RawConn) error, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{
		Timeout:   timeout,
		LocalAddr: laddr,
		Control:   xio.DialControl(s, network, extra),
	}
	return d.DialContext(ctx, network, remote)
}
