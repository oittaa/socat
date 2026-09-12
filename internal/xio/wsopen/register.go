package wsopen

import (
	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"
)

func init() {
	const (
		kind    = addrconfig.AddressKindWebSocket
		connect = addrconfig.AddressRoleConnect
		listen  = addrconfig.AddressRoleListen
		anyIP   = addrconfig.IPFamilyAny
	)
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupWebSocket, Name: "WS", Syntax: "WS:<host>:<port>", Desc: "WebSocket client", Opener: openWSConnect, OptionCaps: xio.CapsTCPConnect, Kind: kind, Role: connect, Family: anyIP})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupWebSocket, Name: "WS-CONNECT", Syntax: "WS-CONNECT:<host>:<port>", Desc: "same as WS", Opener: openWSConnect, OptionCaps: xio.CapsTCPConnect, Kind: kind, Role: connect, Family: anyIP})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupWebSocket, Name: "WSS", Syntax: "WSS:<host>:<port>", Desc: "WebSocket client over TLS", Opener: openWSSConnect, OptionCaps: xio.CapsTLSConnect, Kind: kind, Role: connect, Family: anyIP, Secure: true})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupWebSocket, Name: "WSS-CONNECT", Syntax: "WSS-CONNECT:<host>:<port>", Desc: "same as WSS", Opener: openWSSConnect, OptionCaps: xio.CapsTLSConnect, Kind: kind, Role: connect, Family: anyIP, Secure: true})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupWebSocket, Name: "WS-LISTEN", Syntax: "WS-LISTEN:<port>", Desc: "WebSocket server", Opener: openWSListen, OptionCaps: xio.CapsTCPListen, Kind: kind, Role: listen, Family: anyIP})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupWebSocket, Name: "WS-L", Syntax: "WS-L:<port>", Desc: "same as WS-LISTEN", Opener: openWSListen, OptionCaps: xio.CapsTCPListen, Kind: kind, Role: listen, Family: anyIP})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupWebSocket, Name: "WSS-LISTEN", Syntax: "WSS-LISTEN:<port>", Desc: "WebSocket server over TLS; requires cert=", Opener: openWSSListen, OptionCaps: xio.CapsTLSListen, Kind: kind, Role: listen, Family: anyIP, Secure: true})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupWebSocket, Name: "WSS-L", Syntax: "WSS-L:<port>", Desc: "same as WSS-LISTEN", Opener: openWSSListen, OptionCaps: xio.CapsTLSListen, Kind: kind, Role: listen, Family: anyIP, Secure: true})
}
