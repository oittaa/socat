package xio

import (
	"context"
	"fmt"
	"github.com/oittaa/socat/internal/addrconfig"
	"net"
	"strconv"

	"github.com/oittaa/socat/internal/logx"
)

// ListenPacketWithOptions prepares an unconnected UDP transport socket.
func ListenPacketWithOptions(ctx context.Context, network string, host addrconfig.HostTarget, port addrconfig.PortTarget, s addrconfig.Address) (net.PacketConn, error) {
	if timeout := ConnectTimeout(s); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	laddr, err := ResolveUDPTarget(ctx, s, network, host, port)
	if err != nil {
		return nil, err
	}
	// ListenControl applies send-side IP options before bind.
	lc := net.ListenConfig{Control: ListenControl(s)}
	pc, err := lc.ListenPacket(ctx, network, laddr.String())
	if err != nil {
		return nil, err
	}
	for _, apply := range []func(net.PacketConn, addrconfig.Address) error{
		ApplyLateSocketOptionsToPacketConn, ApplyFDLifecycleToPacketConn,
	} {
		if err := apply(pc, s); err != nil {
			logx.CloseQuiet(pc)
			return nil, err
		}
	}
	if err := ApplyGenericSetsockoptToPacketConn(pc, s, SockoptPhaseConnected); err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}
	return pc, nil
}

// ListenClientPacket binds sourceport, or a reserved port when lowport is set.
func ListenClientPacket(ctx context.Context, network string, host addrconfig.HostTarget, port addrconfig.PortTarget, s addrconfig.Address, g *Global) (net.PacketConn, error) {
	bind := func(p addrconfig.PortTarget) (net.PacketConn, error) {
		return ListenPacketWithOptions(ctx, network, host, p, s)
	}
	if !s.Network.LowPort.Value || (port.Text() != "" && port.Text() != "0") {
		if port.Text() == "" {
			port = addrconfig.PortFromText("0")
		}
		return bind(port)
	}
	var pc net.PacketConn
	_, err := FirstAvailableLowport(func(p int) error {
		if g != nil && g.Log != nil {
			g.Log.Debugf("bind(%s:%d)", host.Original(), p)
		}
		var err error
		pc, err = bind(addrconfig.PortFromText(strconv.Itoa(p)))
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("lowport: cannot bind a port in %d-%d: %w", LowportMin, LowportMax, err)
	}
	return pc, nil
}
