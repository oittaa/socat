package quicopen

import "github.com/oittaa/socat/internal/xio"

func init() {
	xio.Register("QUIC", openQUICConnect)
	xio.Register("QUIC-CONNECT", openQUICConnect)
	xio.Register("QUIC-LISTEN", openQUICListen)
	xio.Register("QUIC-L", openQUICListen)
}
