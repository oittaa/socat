package tunopen

import "github.com/oittaa/socat/internal/xio"

func init() {
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTUN, Name: "TUN", Syntax: "TUN[:<ip>/<bits>]", Desc: "Linux TUN/TAP device", Enabled: func() bool { return xio.FeatureTUN }, Opener: openTUN, OptionCaps: xio.CapsTUN})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupTUN, Name: "INTERFACE", Syntax: "INTERFACE:<ifname>", Desc: "Linux AF_PACKET interface", Enabled: func() bool { return xio.FeatureINTERFACE }, Opener: openINTERFACE, OptionCaps: xio.CapsINTERFACE, Aliases: []string{"IF"}})
}
