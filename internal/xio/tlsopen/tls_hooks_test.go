package tlsopen

import (
	"crypto/tls"

	"github.com/oittaa/socat/internal/addrconfig"
)

func TLSClientConfig(s addrconfig.Address, serverName string) (*tls.Config, error) {
	return TLSClientConfigSettings(s.Type, s.TLS, serverName)
}

func tlsClientConfig(s addrconfig.Address, serverName string) (*tls.Config, error) {
	return TLSClientConfig(s, serverName)
}

func TLSServerConfig(s addrconfig.Address) (*tls.Config, error) {
	return TLSServerConfigSettings(s.Type, s.TLS)
}

func tlsServerConfig(s addrconfig.Address) (*tls.Config, error) {
	return TLSServerConfig(s)
}
