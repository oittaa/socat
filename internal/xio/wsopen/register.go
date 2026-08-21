package wsopen

import "github.com/oittaa/socat/internal/xio"

const groupWS = "WebSocket (Go extra)"

func init() {
	xio.RegisterAddress(xio.AddressDesc{Group: groupWS, Name: "WS", Syntax: "WS:<host>:<port>", Desc: "WebSocket client", Opener: openWSConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: groupWS, Name: "WS-CONNECT", Syntax: "WS-CONNECT:<host>:<port>", Desc: "same as WS", Opener: openWSConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: groupWS, Name: "WSS", Syntax: "WSS:<host>:<port>", Desc: "WebSocket client over TLS", Opener: openWSSConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: groupWS, Name: "WSS-CONNECT", Syntax: "WSS-CONNECT:<host>:<port>", Desc: "same as WSS", Opener: openWSSConnect})
	xio.RegisterAddress(xio.AddressDesc{Group: groupWS, Name: "WS-LISTEN", Syntax: "WS-LISTEN:<port>", Desc: "WebSocket server", Opener: openWSListen})
	xio.RegisterAddress(xio.AddressDesc{Group: groupWS, Name: "WS-L", Syntax: "WS-L:<port>", Desc: "same as WS-LISTEN", Opener: openWSListen})
	xio.RegisterAddress(xio.AddressDesc{Group: groupWS, Name: "WSS-LISTEN", Syntax: "WSS-LISTEN:<port>", Desc: "WebSocket server over TLS; requires cert=", Opener: openWSSListen})
	xio.RegisterAddress(xio.AddressDesc{Group: groupWS, Name: "WSS-L", Syntax: "WSS-L:<port>", Desc: "same as WSS-LISTEN", Opener: openWSSListen})
}
