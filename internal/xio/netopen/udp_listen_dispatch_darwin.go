//go:build darwin

package netopen

import (
	"context"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func udpForkUsesPacketDispatch(s parse.Spec) bool {
	// shut-down needs a dedicated connected socket; reuseaddr=0 needs the
	// exclusive listen-fd handoff. Other fork sessions use one receiver.
	if xio.ShutDownSelected(s) {
		return false
	}
	config, err := xio.OpeningConfig(context.Background(), s)
	if err != nil {
		return false
	}
	if config.Network.ReuseAddr.Set {
		return config.Network.ReuseAddr.Value
	}
	return true
}

func udpForkSharesListenSocket() bool { return false }
