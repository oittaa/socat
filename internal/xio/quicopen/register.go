package quicopen

import (
	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"
)

func init() {
	const (
		connect = addrconfig.AddressRoleConnect
		listen  = addrconfig.AddressRoleListen
		anyIP   = addrconfig.IPFamilyAny
	)
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupQUIC, Name: "QUIC", Syntax: "QUIC:<host>:<port>", Desc: "QUIC byte pipe", Opener: openQUICConnect, OptionCaps: xio.CapsSecureUDPConnect, Role: connect, Family: anyIP})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupQUIC, Name: "QUIC-CONNECT", Syntax: "QUIC-CONNECT:<host>:<port>", Desc: "same as QUIC", Opener: openQUICConnect, OptionCaps: xio.CapsSecureUDPConnect, Role: connect, Family: anyIP})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupQUIC, Name: "QUIC-LISTEN", Syntax: "QUIC-LISTEN:<port>", Desc: "QUIC server; requires cert=", Opener: openQUICListen, OptionCaps: xio.CapsSecureUDPListen, Role: listen, Family: anyIP})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupQUIC, Name: "QUIC-L", Syntax: "QUIC-L:<port>", Desc: "same as QUIC-LISTEN", Opener: openQUICListen, OptionCaps: xio.CapsSecureUDPListen, Role: listen, Family: anyIP})
}
