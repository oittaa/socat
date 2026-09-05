package quicopen

import "github.com/oittaa/socat/internal/xio"

func init() {
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupQUIC, Name: "QUIC", Syntax: "QUIC:<host>:<port>", Desc: "QUIC byte pipe", Opener: openQUICConnect, OptionCaps: xio.CapsSecureUDPConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupQUIC, Name: "QUIC-CONNECT", Syntax: "QUIC-CONNECT:<host>:<port>", Desc: "same as QUIC", Opener: openQUICConnect, OptionCaps: xio.CapsSecureUDPConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupQUIC, Name: "QUIC-LISTEN", Syntax: "QUIC-LISTEN:<port>", Desc: "QUIC server; requires cert=", Opener: openQUICListen, OptionCaps: xio.CapsSecureUDPListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupQUIC, Name: "QUIC-L", Syntax: "QUIC-L:<port>", Desc: "same as QUIC-LISTEN", Opener: openQUICListen, OptionCaps: xio.CapsSecureUDPListen})
}
