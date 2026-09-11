//go:build darwin

package netopen

import (
	"github.com/oittaa/socat/internal/addrconfig"

	"github.com/oittaa/socat/internal/xio"
)

func udpForkUsesPacketDispatch(s addrconfig.Address) bool {
	// shut-down needs a dedicated connected socket; reuseaddr=0 needs the
	// exclusive listen-fd handoff. Other fork sessions use one receiver.
	if xio.ShutDownSelected(s) {
		return false
	}
	config := s
	if config.Network.ReuseAddr.Set {
		return config.Network.ReuseAddr.Value
	}
	return true
}

func udpForkSharesListenSocket() bool { return false }
