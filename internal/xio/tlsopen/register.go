package tlsopen

import "github.com/oittaa/socat/internal/xio"

func init() {
	xio.Register("OPENSSL", openTLSConnect)
	xio.Register("OPENSSL-CONNECT", openTLSConnect)
	xio.Register("SSL", openTLSConnect)
	xio.Register("SSL-CONNECT", openTLSConnect)
	xio.Register("OPENSSL-LISTEN", openTLSListen)
	xio.Register("OPENSSL-L", openTLSListen)
	xio.Register("SSL-LISTEN", openTLSListen)
	xio.Register("SSL-L", openTLSListen)
}
