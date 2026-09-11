// Package dtlsopen implements authenticated DTLS 1.3 datagram endpoints.
package dtlsopen

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/oittaa/socat/internal/dtls13"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/tlsopen"
)

func endpointConfig(ctx context.Context, s parse.Spec, host string, server bool) (*dtls13.Config, error) {
	config, err := xio.OpeningConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	// Older DTLS versions are intentionally excluded; see README security differences.
	if config.TLS.Unsupported.Canonical == "openssl-method" {
		return nil, fmt.Errorf("%s: method selection is not supported; only DTLS 1.3 is available", s.Type)
	}
	var tc *tls.Config
	if server {
		tc, err = tlsopen.TLSServerConfigSettings(s.Type, config.TLS)
	} else {
		tc, err = tlsopen.TLSClientConfigSettings(s.Type, config.TLS, host)
	}
	if err != nil {
		return nil, err
	}
	receiveTimeout, err := xio.RecvTimeoutFromSpec(ctx, s)
	if err != nil {
		return nil, err
	}
	c := &dtls13.Config{
		Certificates: tc.Certificates, RootCAs: tc.RootCAs, ClientCAs: tc.ClientCAs,
		ServerName: tc.ServerName, ClientAuth: tc.ClientAuth,
		InsecureSkipVerify:    tc.InsecureSkipVerify,
		VerifyPeerCertificate: tc.VerifyPeerCertificate, VerifyConnection: tc.VerifyConnection,
		HandshakeTimeout:        xio.HandshakeTimeout(ctx, s),
		HandshakeReadTimeout:    receiveTimeout,
		DisableHandshakeTimeout: xio.HandshakeTimeout(ctx, s) == 0,
	}
	if config.TLS.ALPN.Set {
		protocol := config.TLS.ALPN.Value
		if len(protocol) == 0 || len(protocol) > 255 {
			return nil, fmt.Errorf("alpn: protocol must contain 1 to 255 bytes")
		}
		c.NextProtos = []string{protocol}
	}
	if config.DTLS.MTU.Set {
		c.MTU = config.DTLS.MTU.Value
	}
	c.DisableMigration = config.DTLS.Migration.Set && !config.DTLS.Migration.Value
	c.UnfragmentedProbes = !c.DisableMigration
	if config.DTLS.UnfragmentedProbes.Set {
		c.UnfragmentedProbes = config.DTLS.UnfragmentedProbes.Value
	}
	return c, nil
}
