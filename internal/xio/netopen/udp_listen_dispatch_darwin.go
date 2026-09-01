//go:build darwin

package netopen

import (
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func udpForkUsesPacketDispatch(s parse.Spec) bool {
	// shut-down needs a dedicated connected socket; reuseaddr=0 needs the
	// exclusive listen-fd handoff. Other fork sessions use one receiver.
	return !xio.ShutDownSelected(s) && (!s.HasOption("reuseaddr") || s.BoolOption("reuseaddr"))
}

func udpForkSharesListenSocket() bool { return false }
