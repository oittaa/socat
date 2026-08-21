package proxyopen

import "github.com/oittaa/socat/internal/xio"

const groupProxy = "PROXY and SOCKS"

func init() {
	xio.RegisterAddress(xio.AddressDesc{Group: groupProxy, Name: "PROXY", Syntax: "PROXY:<proxy>:<host>:<port>", Desc: "HTTP CONNECT client", Opener: openProxyConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: groupProxy, Name: "PROXY-CONNECT", Syntax: "PROXY-CONNECT:<proxy>:<host>:<port>", Desc: "same as PROXY", Opener: openProxyConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: groupProxy, Name: "SOCKS4", Syntax: "SOCKS4:<socks>:<host>:<port>", Desc: "SOCKS4 client", Opener: openSOCKS4Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: groupProxy, Name: "SOCKS4A", Syntax: "SOCKS4A:<socks>:<host>:<port>", Desc: "SOCKS4a client", Opener: openSOCKS4AConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: groupProxy, Name: "SOCKS5", Syntax: "SOCKS5:<socks>:<host>:<port>", Desc: "SOCKS5 client", Opener: openSOCKS5Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: groupProxy, Name: "SOCKS5-CONNECT", Syntax: "SOCKS5-CONNECT:<socks>:<host>:<port>", Desc: "same as SOCKS5", Opener: openSOCKS5Connect})
	xio.RegisterAddress(xio.AddressDesc{Group: groupProxy, Name: "SOCKS5-LISTEN", Syntax: "SOCKS5-LISTEN:<socks>:<host>:<port>", Desc: "SOCKS5 BIND (remote listen)", Opener: openSOCKS5Listen})
	xio.RegisterAddress(xio.AddressDesc{Group: groupProxy, Name: "SOCKS5-BIND", Syntax: "SOCKS5-BIND:<socks>:<host>:<port>", Desc: "same as SOCKS5-LISTEN", Opener: openSOCKS5Listen})
}
