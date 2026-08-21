package quicopen

import "github.com/oittaa/socat/internal/xio"

const groupQUIC = "QUIC (Go extra, not HTTP/3)"

func init() {
	xio.RegisterAddress(xio.AddressDesc{Group: groupQUIC, Name: "QUIC", Syntax: "QUIC:<host>:<port>", Desc: "QUIC byte pipe", Opener: openQUICConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: groupQUIC, Name: "QUIC-CONNECT", Syntax: "QUIC-CONNECT:<host>:<port>", Desc: "same as QUIC", Opener: openQUICConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: groupQUIC, Name: "QUIC-LISTEN", Syntax: "QUIC-LISTEN:<port>", Desc: "QUIC server; requires cert=", Opener: openQUICListen})
	xio.RegisterAddress(xio.AddressDesc{Group: groupQUIC, Name: "QUIC-L", Syntax: "QUIC-L:<port>", Desc: "same as QUIC-LISTEN", Opener: openQUICListen})
}
