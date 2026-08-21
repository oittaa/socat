// Package testcert generates throwaway CAs and leaf certificates for tests.
// Only _test.go files import it, so it is never linked into the shipped
// binaries.
package testcert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Authority is a self-signed certificate authority for signing test leaves.
type Authority struct {
	Cert *x509.Certificate
	Key  ed25519.PrivateKey
	DER  []byte

	nextSerial int64
}

// Leaf is a certificate signed by an Authority.
type Leaf struct {
	Cert *x509.Certificate
	Key  ed25519.PrivateKey
	DER  []byte
}

// NewAuthority creates a self-signed CA valid for a day.
func NewAuthority(commonName string) (*Authority, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Authority{Cert: cert, Key: key, DER: der, nextSerial: 1}, nil
}

// Leaf signs a certificate. Empty dns/ips yield a classic CN-only
// certificate; non-empty lists become the subjectAltName entries that gate
// CN fallback during verification.
func (a *Authority) Leaf(commonName string, usage []x509.ExtKeyUsage, ips []net.IP, dns []string) (*Leaf, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	a.nextSerial++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(a.nextSerial),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           usage,
		IPAddresses:           ips,
		DNSNames:              dns,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.Cert, pub, a.Key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Leaf{Cert: cert, Key: key, DER: der}, nil
}

// TLS returns the leaf ready for a crypto/tls Config.
func (l *Leaf) TLS() tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{l.DER}, PrivateKey: l.Key}
}

// CertPEM returns the leaf certificate as PEM.
func (l *Leaf) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: l.DER})
}

// KeyPEM returns the private key as PKCS#8 PEM.
func (l *Leaf) KeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(l.Key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// WriteCertPEM writes a single certificate as PEM.
func WriteCertPEM(path string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// WriteCertAndKey writes the leaf certificate and its key as separate PEM
// files named <base>.crt / <base>.key inside dir.
func (l *Leaf) WriteCertAndKey(dir, base string) (certPath, keyPath string, err error) {
	keyPEM, err := l.KeyPEM()
	if err != nil {
		return "", "", err
	}
	certPath = filepath.Join(dir, base+".crt")
	keyPath = filepath.Join(dir, base+".key")
	if err := os.WriteFile(certPath, l.CertPEM(), 0o600); err != nil {
		return "", "", fmt.Errorf("write %s: %w", certPath, err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("write %s: %w", keyPath, err)
	}
	return certPath, keyPath, nil
}

// WriteTempListenCert writes a short-lived self-signed Ed25519 server
// certificate and key as one PEM file. Listen addresses require this via
// cert=; tests point TLS-LISTEN/QUIC-LISTEN/WSS-LISTEN at the returned path.
func WriteTempListenCert(dir string) (string, error) {
	cert, err := EphemeralSelfSigned()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "listen.pem")
	if err := writeCertKeyPEM(path, cert); err != nil {
		return "", err
	}
	return path, nil
}

func writeCertKeyPEM(path string, cert tls.Certificate) error {
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("tls: empty certificate")
	}
	var b []byte
	for _, der := range cert.Certificate {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return err
	}
	b = append(b, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	return os.WriteFile(path, b, 0o600)
}

// EphemeralSelfSigned builds a short-lived self-signed Ed25519 certificate.
func EphemeralSelfSigned() (tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "socat-ephemeral"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}
