// Package dtlsopen implements authenticated DTLS 1.3 datagram endpoints.
package dtlsopen

import (
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/dtls13"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/tlsopen"
)

func endpointConfig(s parse.Spec, host string, server bool) (*dtls13.Config, error) {
	// Older DTLS versions are intentionally excluded; see README security differences.
	if s.HasOption("openssl-method") {
		return nil, fmt.Errorf("%s: method selection is not supported; only DTLS 1.3 is available", s.Type)
	}
	for _, name := range []string{"openssl-min-proto-version", "openssl-max-proto-version"} {
		if !s.HasOption(name) {
			continue
		}
		value := strings.ToUpper(s.OptionValue(name, ""))
		var version int
		switch value {
		case "DTLS1", "DTLS1.0", "DTLSV1", "DTLSV1.0":
			version = 10
		case "DTLS1.2", "DTLSV1.2":
			version = 12
		case "DTLS1.3", "DTLSV1.3":
			version = 13
		default:
			return nil, fmt.Errorf("%s: invalid DTLS protocol version %q", name, value)
		}
		if name == "openssl-max-proto-version" && version < 13 {
			return nil, fmt.Errorf("%s: only DTLS 1.3 is supported", name)
		}
	}
	credentials := s
	credentials.Options = nil
	for _, option := range s.Options {
		switch parse.CanonicalOptionName(option.Name) {
		case "openssl-min-proto-version", "openssl-max-proto-version":
		default:
			credentials.Options = append(credentials.Options, option)
		}
	}
	var tc *tls.Config
	var err error
	if server {
		tc, err = tlsopen.TLSServerConfig(credentials)
	} else {
		tc, err = tlsopen.TLSClientConfig(credentials, host)
	}
	if err != nil {
		return nil, err
	}
	c := &dtls13.Config{
		Certificates: tc.Certificates, RootCAs: tc.RootCAs, ClientCAs: tc.ClientCAs,
		ServerName: tc.ServerName, ClientAuth: tc.ClientAuth,
		InsecureSkipVerify:    tc.InsecureSkipVerify,
		VerifyPeerCertificate: tc.VerifyPeerCertificate, VerifyConnection: tc.VerifyConnection,
		HandshakeTimeout:        xio.HandshakeTimeout(s),
		DisableHandshakeTimeout: xio.HandshakeTimeout(s) == 0,
	}
	if s.HasOption("alpn") {
		protocol := s.OptionValue("alpn", "")
		if len(protocol) == 0 || len(protocol) > 255 {
			return nil, fmt.Errorf("alpn: protocol must contain 1 to 255 bytes")
		}
		c.NextProtos = []string{protocol}
	}
	if s.HasOption("dtls-mtu") {
		c.MTU, err = strconv.Atoi(s.OptionValue("dtls-mtu", ""))
		if err != nil || c.MTU < 256 || c.MTU > 65507 {
			return nil, fmt.Errorf("dtls-mtu: value must be between 256 and 65507")
		}
	}
	c.DisableMigration = s.HasOption("dtls-migration") && !s.BoolOption("dtls-migration")
	return c, nil
}
