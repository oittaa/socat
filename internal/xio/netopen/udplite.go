package netopen

import (
	"context"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

// RFC 3828 / IANA UDP-Lite (IP protocol 136). unix.IPPROTO_UDPLITE is 0x88
// on Linux. Go net has no "udp-lite" network, so named UDPLITE* types open
// SOCK_DGRAM + this protocol and wrap the fd as *net.UDPConn. Classic also
// builds UDP-Lite on other platforms with IPPROTO_UDPLITE (including FreeBSD);
// this port is Linux-only because the repository does not yet build for FreeBSD.
const ipprotoUDPLITE = 136

func ipDgramProto(s parse.Spec) int {
	t := strings.ToUpper(strings.TrimSpace(s.Type))
	if alias, ok := xio.ClassicAddressAliases[t]; ok {
		t = alias
	}
	if strings.HasPrefix(t, "UDPLITE") {
		return ipprotoUDPLITE
	}
	return 0
}

func listenPacketForSpec(ctx context.Context, network, address string, s parse.Spec) (net.PacketConn, error) {
	if proto := ipDgramProto(s); proto != 0 {
		laddr, err := net.ResolveUDPAddr(network, address)
		if err != nil {
			return nil, err
		}
		return listenIPDgram(ctx, network, laddr, s, proto)
	}
	lc := udpListenConfig(s)
	return lc.ListenPacket(ctx, network, address)
}

func dialUDPForSpec(ctx context.Context, network string, laddr net.Addr, remote string, s parse.Spec, extra func(string, string, syscall.RawConn) error, timeout time.Duration) (net.Conn, error) {
	if proto := ipDgramProto(s); proto != 0 {
		var la *net.UDPAddr
		if laddr != nil {
			var ok bool
			la, ok = laddr.(*net.UDPAddr)
			if !ok {
				return nil, fmt.Errorf("UDPLITE: unexpected local addr type %T", laddr)
			}
		}
		ra, err := net.ResolveUDPAddr(network, remote)
		if err != nil {
			return nil, err
		}
		return dialIPDgram(ctx, network, la, ra, s, proto, extra, timeout)
	}
	d := net.Dialer{
		Timeout:   timeout,
		LocalAddr: laddr,
		Control:   xio.DialControl(s, network, extra),
	}
	return d.DialContext(ctx, network, remote)
}
