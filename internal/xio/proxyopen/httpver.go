package proxyopen

import (
	"fmt"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio/tlsopen"
)

func rejectProxyPlaintextPolicy(config addrconfig.Address) error {
	major, _ := proxyHTTPVersion(config.Proxy)
	h2c := config.Proxy.H2C.Value
	if h2c && major != addrconfig.HTTPVersion2 {
		return fmt.Errorf("h2c requires http-version=2")
	}
	if config.Proxy.IgnoreCR.Value && major >= addrconfig.HTTPVersion2 {
		return fmt.Errorf("ignorecr applies only to HTTP/1 CONNECT responses")
	}
	if major <= addrconfig.HTTPVersion11 || (major == addrconfig.HTTPVersion2 && h2c) {
		return tlsopen.RejectPROXYTLSOnPlaintext(config.Type, config.TLS)
	}
	return nil
}

func proxyHTTPVersion(p addrconfig.Proxy) (addrconfig.HTTPVersion, string) {
	switch p.HTTPVersion {
	case addrconfig.HTTPVersion11:
		return addrconfig.HTTPVersion11, "1.1"
	case addrconfig.HTTPVersion2:
		return addrconfig.HTTPVersion2, "2"
	case addrconfig.HTTPVersion3:
		return addrconfig.HTTPVersion3, "3"
	default:
		return addrconfig.HTTPVersion10, "1.0"
	}
}

func proxyPortTarget(p addrconfig.Proxy) addrconfig.PortTarget {
	if p.PortSet && p.Port.Text() != "" {
		return p.Port
	}
	return addrconfig.PortFromText("8080")
}

func proxyPortText(p addrconfig.Proxy) string {
	return proxyPortTarget(p).Text()
}

func proxyResolveTarget(p addrconfig.Proxy) bool {
	if p.Resolve.Set {
		return p.Resolve.Value
	}
	return true
}

func proxyALPN(settings addrconfig.TLS, def string) string {
	if settings.ALPN.Set && settings.ALPN.Value != "" {
		return settings.ALPN.Value
	}
	return def
}
