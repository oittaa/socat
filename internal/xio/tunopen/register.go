package tunopen

import "github.com/oittaa/socat/internal/xio"

func init() {
	xio.Register("TUN", openTUN)
	xio.Register("INTERFACE", openINTERFACE)
}
