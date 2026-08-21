package wsopen

import "github.com/oittaa/socat/internal/xio"

func init() {
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupWebSocket, Name: "WS", Syntax: "WS:<host>:<port>", Desc: "WebSocket client", Opener: openWSConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupWebSocket, Name: "WS-CONNECT", Syntax: "WS-CONNECT:<host>:<port>", Desc: "same as WS", Opener: openWSConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupWebSocket, Name: "WSS", Syntax: "WSS:<host>:<port>", Desc: "WebSocket client over TLS", Opener: openWSSConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupWebSocket, Name: "WSS-CONNECT", Syntax: "WSS-CONNECT:<host>:<port>", Desc: "same as WSS", Opener: openWSSConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupWebSocket, Name: "WS-LISTEN", Syntax: "WS-LISTEN:<port>", Desc: "WebSocket server", Opener: openWSListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupWebSocket, Name: "WS-L", Syntax: "WS-L:<port>", Desc: "same as WS-LISTEN", Opener: openWSListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupWebSocket, Name: "WSS-LISTEN", Syntax: "WSS-LISTEN:<port>", Desc: "WebSocket server over TLS; requires cert=", Opener: openWSSListen})
	xio.RegisterAddress(xio.AddressDesc{Group: xio.GroupWebSocket, Name: "WSS-L", Syntax: "WSS-L:<port>", Desc: "same as WSS-LISTEN", Opener: openWSSListen})
}
