// Certificate, key, and CA trust-store loading plus the ephemeral test cert.
package tlsopen

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oittaa/socat/internal/parse"
)

// errDSAUnsupported is returned when a PEM contains a DSA private key.
// DSA is deprecated; Go crypto/tls does not support DSA keys.
var errDSAUnsupported = fmt.Errorf("DSA private keys are not supported (deprecated)")

// loadKeyPair loads cert+key from separate files or a combined PEM (classic .pem).
func loadKeyPair(certPath, keyPath string) (tls.Certificate, error) {
	if keyPath == "" {
		// Combined PEM: PRIVATE KEY + CERTIFICATE (+ optional DH)
		data, err := os.ReadFile(certPath) // #nosec G304 -- OPEN/FILE/cert= must open the path the user gave
		if err != nil {
			return tls.Certificate{}, err
		}
		if pemHasDSAPrivateKey(data) {
			return tls.Certificate{}, fmt.Errorf("cert %s: %w", certPath, errDSAUnsupported)
		}
		// tls.X509KeyPair accepts cert PEM then key PEM, or we try both orders.
		certPEM, keyPEM := splitCertKeyPEM(data)
		if len(certPEM) == 0 || len(keyPEM) == 0 {
			return tls.Certificate{}, fmt.Errorf("cert %s: need both certificate and private key in PEM", certPath)
		}
		return tls.X509KeyPair(certPEM, keyPEM)
	}
	keyData, err := os.ReadFile(keyPath) // #nosec G304 -- OPEN/FILE/cert= must open the path the user gave
	if err != nil {
		return tls.Certificate{}, err
	}
	if pemHasDSAPrivateKey(keyData) {
		return tls.Certificate{}, fmt.Errorf("key %s: %w", keyPath, errDSAUnsupported)
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}

func pemHasDSAPrivateKey(data []byte) bool {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return false
		}
		if block.Type == "DSA PRIVATE KEY" {
			return true
		}
	}
}

func splitCertKeyPEM(data []byte) (certPEM, keyPEM []byte) {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		b := pem.EncodeToMemory(block)
		switch block.Type {
		case "CERTIFICATE":
			certPEM = append(certPEM, b...)
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
			// DSA PRIVATE KEY intentionally omitted — rejected in loadKeyPair.
			keyPEM = append(keyPEM, b...)
		}
	}
	return certPEM, keyPEM
}

func loadCAPool(s parse.Spec) (*x509.CertPool, error) {
	cafile := s.OptionValue("cafile", "")
	if cafile == "" {
		cafile = s.OptionValue("ca", "")
	}
	capath := s.OptionValue("capath", "")
	if cafile == "" && capath == "" {
		return nil, nil
	}
	pool := x509.NewCertPool()
	n := 0
	if cafile != "" {
		added, err := appendCABytes(pool, cafile)
		if err != nil {
			return nil, fmt.Errorf("cafile: %w", err)
		}
		n += added
	}
	if capath != "" {
		added, err := appendCAPath(pool, capath)
		if err != nil {
			return nil, err
		}
		n += added
	}
	if n == 0 {
		return nil, fmt.Errorf("cafile/capath: no certificates found")
	}
	return pool, nil
}

// loadVerifyRoots is the trust store for verify=1: cafile/capath, else the system pool
// (classic SSL_CTX_set_default_verify_paths).
func loadVerifyRoots(s parse.Spec) (*x509.CertPool, error) {
	pool, err := loadCAPool(s)
	if err != nil {
		return nil, err
	}
	if pool != nil {
		return pool, nil
	}
	return x509.SystemCertPool()
}

func appendCABytes(pool *x509.CertPool, path string) (int, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- OPEN/FILE/cert= must open the path the user gave
	if err != nil {
		return 0, err
	}
	if pool.AppendCertsFromPEM(data) {
		return 1, nil
	}
	n := 0
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			continue
		}
		pool.AddCert(c)
		n++
	}
	if n == 0 {
		if c, e := x509.ParseCertificate(data); e == nil {
			pool.AddCert(c)
			return 1, nil
		}
		return 0, fmt.Errorf("%s: no certificates found", path)
	}
	return n, nil
}

func appendCAPath(pool *x509.CertPool, dir string) (int, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("capath: %w", err)
	}
	n := 0
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			// Hashed OpenSSL capath often uses symlinks; resolve those.
			st, e2 := os.Stat(p)
			if e2 != nil || !st.Mode().IsRegular() {
				continue
			}
		}
		added, err := appendCABytes(pool, p)
		if err != nil {
			continue
		}
		n += added
	}
	if n == 0 {
		return 0, fmt.Errorf("capath %s: no certificates found", dir)
	}
	return n, nil
}
