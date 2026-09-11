package netopen

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"
)

func listenPacketForSpec(ctx context.Context, network string, laddr *net.UDPAddr, s addrconfig.Address) (net.PacketConn, error) {
	lc := udpListenConfig(s)
	return lc.ListenPacket(ctx, network, laddrString(network, laddr))
}

func dialUDPForSpec(req dialRequest, laddr net.Addr, remote *net.UDPAddr) (net.Conn, error) {
	if remote == nil {
		return nil, net.ErrClosed
	}
	if err := rejectUDPRemoteFamily(req.network, remote); err != nil {
		return nil, err
	}
	matched, err := xio.MatchLocalPacketAddr(req.network, laddr)
	if err != nil {
		return nil, err
	}
	local, err := localUDPAddrForDial(req.network, matched, remote)
	if err != nil {
		return nil, err
	}
	ctx, cancel := req.withTimeout()
	defer cancel()
	lc := net.ListenConfig{Control: xio.DialControl(req.config, req.network, req.control)}
	pc, err := lc.ListenPacket(ctx, req.network, laddrString(req.network, local))
	if err != nil {
		return nil, err
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("UDP: unexpected conn type %T", pc)
	}
	if err := connectUDPPeer(uc, remote); err != nil {
		_ = uc.Close()
		return nil, err
	}
	return uc, nil
}

func rejectUDPRemoteFamily(network string, remote *net.UDPAddr) error {
	if remote == nil || remote.IP == nil {
		return nil
	}
	is4 := remote.IP.To4() != nil
	if strings.HasSuffix(network, "6") && is4 {
		return fmt.Errorf("address family mismatch")
	}
	if strings.HasSuffix(network, "4") && !is4 {
		return fmt.Errorf("address family mismatch")
	}
	return nil
}

func localUDPAddrForDial(network string, laddr net.Addr, remote *net.UDPAddr) (*net.UDPAddr, error) {
	if laddr != nil {
		u, ok := laddr.(*net.UDPAddr)
		if !ok {
			return nil, fmt.Errorf("UDP: unexpected local addr type %T", laddr)
		}
		return u, nil
	}
	ip := net.IPv4zero
	if strings.HasSuffix(network, "6") || (remote != nil && remote.IP != nil && remote.IP.To4() == nil) {
		ip = net.IPv6zero
	}
	return &net.UDPAddr{IP: ip, Port: 0}, nil
}
