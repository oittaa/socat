package wsopen

import "github.com/oittaa/socat/internal/xio"

func init() {
	xio.Register("WS", openWSConnect)
	xio.Register("WS-CONNECT", openWSConnect)
	xio.Register("WSS", openWSSConnect)
	xio.Register("WSS-CONNECT", openWSSConnect)
	xio.Register("WS-LISTEN", openWSListen)
	xio.Register("WS-L", openWSListen)
	xio.Register("WSS-LISTEN", openWSSListen)
	xio.Register("WSS-L", openWSSListen)
}
