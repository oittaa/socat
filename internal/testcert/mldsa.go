package testcert

import (
	"crypto/mldsa"
	"crypto/rand"
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

// Bundle is a CA plus server and client leaves written as PEM files.
type Bundle struct {
	CAFile     string
	ServerCert string
	ServerKey  string
	ClientCert string
	ClientKey  string
}

// WriteMLDSA44Trust writes an ML-DSA-44 CA and mTLS leaves (FIPS 204).
// crypto/mldsa.GenerateKey fails on the FIPS 140-3 Go Cryptographic Module v1.0.0.
func WriteMLDSA44Trust(dir string) (Bundle, error) {
	caKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		return Bundle{}, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "socat-mldsa-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.PublicKey(), caKey)
	if err != nil {
		return Bundle{}, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return Bundle{}, err
	}
	caFile := filepath.Join(dir, "ca.crt")
	if err := WriteCertPEM(caFile, caDER); err != nil {
		return Bundle{}, err
	}

	srvCert, srvKey, err := writeMLDSA44Leaf(dir, "localhost", 2, caCert, caKey,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		[]net.IP{net.ParseIP("127.0.0.1")}, []string{"localhost"})
	if err != nil {
		return Bundle{}, err
	}
	cliCert, cliKey, err := writeMLDSA44Leaf(dir, "client", 3, caCert, caKey,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{
		CAFile:     caFile,
		ServerCert: srvCert,
		ServerKey:  srvKey,
		ClientCert: cliCert,
		ClientKey:  cliKey,
	}, nil
}

func writeMLDSA44Leaf(dir, cn string, serial int64, ca *x509.Certificate, caKey *mldsa.PrivateKey, usage []x509.ExtKeyUsage, ips []net.IP, dns []string) (certPath, keyPath string, err error) {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usage,
		IPAddresses:  ips,
		DNSNames:     dns,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, sk.PublicKey(), caKey)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		return "", "", err
	}
	certPath = filepath.Join(dir, cn+".crt")
	keyPath = filepath.Join(dir, cn+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		return "", "", fmt.Errorf("write %s: %w", certPath, err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return "", "", fmt.Errorf("write %s: %w", keyPath, err)
	}
	return certPath, keyPath, nil
}
