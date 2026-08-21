package tunopen

import "github.com/oittaa/socat/internal/xio"

const groupTUN = "Linux TUN / INTERFACE"

func init() {
	tunEnabled := func() bool { return xio.FeatureTUN || xio.FeatureINTERFACE }

	xio.RegisterAddress(xio.AddressDesc{Group: groupTUN, Name: "TUN", Syntax: "TUN[:<ip>/<bits>]", Desc: "Linux TUN/TAP device", Enabled: tunEnabled, Opener: openTUN})
	xio.RegisterAddress(xio.AddressDesc{Group: groupTUN, Name: "INTERFACE", Syntax: "INTERFACE:<ifname>", Desc: "Linux AF_PACKET interface", Enabled: tunEnabled, Opener: openINTERFACE})
}
