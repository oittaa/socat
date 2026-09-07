package dtls13

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// Config supplies credentials and datagram limits. Certificates, private keys,
// trust pools, and callbacks must not be mutated while a connection uses them.
type Config struct {
	Certificates          []tls.Certificate
	RootCAs               *x509.CertPool
	ClientCAs             *x509.CertPool
	ServerName            string
	NextProtos            []string
	ClientAuth            tls.ClientAuthType
	InsecureSkipVerify    bool
	VerifyPeerCertificate func([][]byte, [][]*x509.Certificate) error
	VerifyConnection      func(tls.ConnectionState) error
	Time                  func() time.Time
	CipherSuites          []uint16
	CurvePreferences      []tls.CurveID

	// MTU is the maximum UDP payload size; zero selects 1200 bytes.
	MTU int
	// ConnectionIDLength defaults to 8. DisableMigration disables CID and RRC.
	ConnectionIDLength int
	DisableMigration   bool
	// HandshakeTimeout defaults to 30 seconds and must be positive if set.
	HandshakeTimeout time.Duration
	// HandshakeReadTimeout bounds each receive wait during negotiation.
	// Zero disables it; received fragments and retransmissions restart the wait.
	HandshakeReadTimeout time.Duration
	// DisableHandshakeTimeout removes the absolute handshake deadline.
	// Protocol retransmission limits still apply.
	DisableHandshakeTimeout bool
	// MaxConnections bounds simultaneous associations at a listener.
	MaxConnections int
	// AcceptPeer filters initial and migrated peer addresses before processing.
	AcceptPeer func(netip.AddrPort) bool
}

func prepareConfig(config *Config, server bool) (*Config, error) {
	if config == nil {
		return nil, fmt.Errorf("dtls: configuration is required")
	}
	c := *config
	c.Certificates = slices.Clone(c.Certificates)
	c.NextProtos = slices.Clone(c.NextProtos)
	c.CipherSuites = slices.Clone(c.CipherSuites)
	c.CurvePreferences = slices.Clone(c.CurvePreferences)
	if c.MTU == 0 {
		c.MTU = 1200
	}
	if c.MTU < 256 || c.MTU > 65507 {
		return nil, fmt.Errorf("dtls: MTU must be between 256 and 65507")
	}
	if c.ConnectionIDLength == 0 {
		c.ConnectionIDLength = 8
	}
	if c.ConnectionIDLength < 1 || c.ConnectionIDLength > 32 {
		return nil, fmt.Errorf("dtls: connection ID length must be between 1 and 32")
	}
	if c.DisableMigration {
		c.ConnectionIDLength = 0
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 30 * time.Second
	}
	if c.HandshakeTimeout < 0 {
		return nil, fmt.Errorf("dtls: handshake timeout must be positive")
	}
	if c.HandshakeReadTimeout < 0 {
		return nil, fmt.Errorf("dtls: handshake receive timeout must not be negative")
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = 256
	}
	if c.MaxConnections < 1 || c.MaxConnections > 65535 {
		return nil, fmt.Errorf("dtls: connection limit must be between 1 and 65535")
	}
	if len(c.CipherSuites) == 0 {
		c.CipherSuites = defaultCipherSuites()
	}
	for i, suite := range c.CipherSuites {
		if _, err := suiteFor(suite); err != nil {
			return nil, err
		}
		if slices.Contains(c.CipherSuites[:i], suite) {
			return nil, fmt.Errorf("dtls: duplicate cipher suite")
		}
	}
	if len(c.CurvePreferences) == 0 {
		c.CurvePreferences = defaultGroups()
	}
	for i, group := range c.CurvePreferences {
		if _, err := groupFor(uint16(group)); err != nil {
			return nil, err
		}
		if slices.Contains(c.CurvePreferences[:i], group) {
			return nil, fmt.Errorf("dtls: duplicate key-exchange group")
		}
	}
	if len(c.NextProtos) != 0 {
		if _, err := encodeALPN(c.NextProtos); err != nil {
			return nil, err
		}
	}
	if c.ClientAuth < tls.NoClientCert || c.ClientAuth > tls.RequireAndVerifyClientCert {
		return nil, fmt.Errorf("dtls: invalid client authentication policy")
	}
	if !server && !c.InsecureSkipVerify && c.ServerName == "" {
		return nil, fmt.Errorf("dtls: server name is required for certificate verification")
	}
	if server && len(c.Certificates) == 0 {
		return nil, fmt.Errorf("dtls: server certificate is required")
	}
	for _, cert := range c.Certificates {
		if len(cert.Certificate) == 0 {
			return nil, errCertificate
		}
		if _, err := encodeCertificate(cert.Certificate, nil); err != nil {
			return nil, err
		}
		signer, ok := cert.PrivateKey.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("dtls: certificate private key cannot sign")
		}
		if _, err := selectSignature(signer.Public(), signatureSchemes); err != nil {
			return nil, err
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, err
		}
		public, err := x509.MarshalPKIXPublicKey(signer.Public())
		if err != nil {
			return nil, err
		}
		certificatePublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if err != nil {
			return nil, err
		}
		if !slices.Equal(public, certificatePublic) {
			return nil, fmt.Errorf("dtls: certificate and private key do not match")
		}
	}
	return &c, nil
}

func (c *Config) now() time.Time {
	if c.Time != nil {
		return c.Time()
	}
	return time.Now()
}
