package testutil

import (
	"context"
	"net"
	"strings"
)

// Occupied reports whether a bind of network/addr fails with BindBusy.
// Other listen errors — including a cancelled context, an invalid address,
// and unexpected permission or family failures — are returned to the caller
// instead of being treated as occupancy.
func Occupied(ctx context.Context, lc net.ListenConfig, network, addr string) (bool, error) {
	if strings.HasPrefix(network, "udp") {
		pc, err := lc.ListenPacket(ctx, network, addr)
		if err != nil {
			return listenOccupancy(err)
		}
		_ = pc.Close()
		return false, nil
	}
	ln, err := lc.Listen(ctx, network, addr)
	if err != nil {
		return listenOccupancy(err)
	}
	_ = ln.Close()
	return false, nil
}

func listenOccupancy(err error) (bool, error) {
	if err == nil {
		return false, nil
	}
	if BindBusy(err) {
		return true, nil
	}
	return false, err
}
