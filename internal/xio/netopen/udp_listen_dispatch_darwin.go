//go:build darwin

package netopen

import (
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func udpForkUsesPacketDispatch(s parse.Spec) bool {
	return !xio.ShutDownSelected(s) && (!s.HasOption("reuseaddr") || s.BoolOption("reuseaddr"))
}

func udpForkSharesListenSocket() bool { return false }
