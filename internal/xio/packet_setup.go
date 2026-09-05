package xio

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
)

// ListenPacketWithOptions prepares an unconnected UDP transport socket.
func ListenPacketWithOptions(ctx context.Context, network, addr string, s parse.Spec) (net.PacketConn, error) {
	if timeout := ConnectTimeout(s); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	laddr, err := ResolveUDPAddr(ctx, s, network, addr)
	if err != nil {
		return nil, err
	}
	// ListenControl applies send-side IP options before bind.
	lc := net.ListenConfig{Control: ListenControl(s)}
	pc, err := lc.ListenPacket(ctx, network, laddr.String())
	if err != nil {
		return nil, err
	}
	for _, apply := range []func(net.PacketConn, parse.Spec) error{
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
func ListenClientPacket(ctx context.Context, network, bindHost, sourceport string, s parse.Spec, g *Global) (net.PacketConn, error) {
	bind := func(port string) (net.PacketConn, error) {
		return ListenPacketWithOptions(ctx, network, net.JoinHostPort(StripBrackets(bindHost), port), s)
	}
	if !s.BoolOption("lowport") || (sourceport != "" && sourceport != "0") {
		if sourceport == "" {
			sourceport = "0"
		}
		return bind(sourceport)
	}
	var pc net.PacketConn
	_, err := FirstAvailableLowport(func(port int) error {
		if g != nil && g.Log != nil {
			g.Log.Debugf("bind(%s:%d)", bindHost, port)
		}
		var err error
		pc, err = bind(strconv.Itoa(port))
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("lowport: cannot bind a port in %d-%d: %w", LowportMin, LowportMax, err)
	}
	return pc, nil
}
