// Package dtlsopen implements authenticated DTLS 1.3 datagram endpoints.
package dtlsopen

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/oittaa/socat/internal/addrconfig"

	"github.com/oittaa/socat/internal/dtls13"
	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/tlsopen"
)

func endpointConfig(ctx context.Context, s addrconfig.Address, host string, server bool) (*dtls13.Config, error) {
	// Older DTLS versions are intentionally excluded; see README security differences.
	if s.TLS.UnsupportedCanonical == "openssl-method" {
		return nil, fmt.Errorf("%s: method selection is not supported; only DTLS 1.3 is available", s.Type)
	}
	var tc *tls.Config
	var err error
	if server {
		tc, err = tlsopen.TLSServerConfigSettings(s.Type, s.TLS)
	} else {
		tc, err = tlsopen.TLSClientConfigSettings(s.Type, s.TLS, host)
	}
	if err != nil {
		return nil, err
	}
	receiveTimeout, err := xio.RecvTimeout(s)
	if err != nil {
		return nil, err
	}
	c := &dtls13.Config{
		Certificates: tc.Certificates, RootCAs: tc.RootCAs, ClientCAs: tc.ClientCAs,
		ServerName: tc.ServerName, ClientAuth: tc.ClientAuth,
		InsecureSkipVerify:    tc.InsecureSkipVerify,
		VerifyPeerCertificate: tc.VerifyPeerCertificate, VerifyConnection: tc.VerifyConnection,
		HandshakeTimeout:        xio.HandshakeTimeout(s),
		HandshakeReadTimeout:    receiveTimeout,
		DisableHandshakeTimeout: xio.HandshakeTimeout(s) == 0,
	}
	if s.TLS.ALPN.Set {
		protocol := s.TLS.ALPN.Value
		if len(protocol) == 0 || len(protocol) > 255 {
			return nil, fmt.Errorf("alpn: protocol must contain 1 to 255 bytes")
		}
		c.NextProtos = []string{protocol}
	}
	if s.TLS.DTLSMTU.Set {
		c.MTU = s.TLS.DTLSMTU.Value
	}
	c.DisableMigration = s.TLS.DTLSMigration.Set && !s.TLS.DTLSMigration.Value
	c.UnfragmentedProbes = !c.DisableMigration
	if s.TLS.DTLSUnfragmentedProbes.Set {
		c.UnfragmentedProbes = s.TLS.DTLSUnfragmentedProbes.Value
	}
	return c, nil
}
