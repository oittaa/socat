// Package all imports every address opener so xio.Register init runs.
package all

import (
	_ "github.com/oittaa/socat/internal/xio/fileopen"
	_ "github.com/oittaa/socat/internal/xio/netopen"
	_ "github.com/oittaa/socat/internal/xio/posixmqopen"
	_ "github.com/oittaa/socat/internal/xio/proxyopen"
	_ "github.com/oittaa/socat/internal/xio/quicopen"
	_ "github.com/oittaa/socat/internal/xio/tlsopen"
	_ "github.com/oittaa/socat/internal/xio/tunopen"
	_ "github.com/oittaa/socat/internal/xio/wsopen"
)
