package proxyopen

import "github.com/oittaa/socat/internal/xio"

func init() {
	xio.Register("PROXY", openProxyConnect)
	xio.Register("PROXY-CONNECT", openProxyConnect)
	xio.Register("SOCKS4", openSOCKS4Connect)
	xio.Register("SOCKS4A", openSOCKS4AConnect)
	xio.Register("SOCKS5", openSOCKS5Connect)
	xio.Register("SOCKS5-CONNECT", openSOCKS5Connect)
	xio.Register("SOCKS5-LISTEN", openSOCKS5Listen)
	xio.Register("SOCKS5-BIND", openSOCKS5Listen)
}
