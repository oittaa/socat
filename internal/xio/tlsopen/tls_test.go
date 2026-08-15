package tlsopen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

func TestLoadKeyPairRejectsDSA(t *testing.T) {
	// Type label alone is enough for our early rejection (body need not parse).
	pemData := []byte(`-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHH0V2o0X3dMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yMDAxMDEwMDAwMDBaFw0zMDAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAu1SU1F4ByV2/9b0E
-----END CERTIFICATE-----
-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END DSA PRIVATE KEY-----
`)
	dir := t.TempDir()
	path := filepath.Join(dir, "dsa.pem")
	if err := os.WriteFile(path, pemData, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadKeyPair(path, "")
	if err == nil {
		t.Fatal("expected DSA rejection")
	}
	if !errors.Is(err, errDSAUnsupported) {
		t.Fatalf("got %v want errDSAUnsupported", err)
	}
}

func TestPostQuantumHybridKeyExchange(t *testing.T) {
	// Classic test.sh has no post-quantum coverage. Go 1.24+ crypto/tls
	// defaults to the X25519MLKEM768 hybrid KEM; assert we negotiate it.
	cert, err := ephemeralSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srvCfg := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
	}
	cliCfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
	}

	errCh := make(chan error, 1)
	var srvCurve tls.CurveID
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		tc := tls.Server(c, srvCfg)
		if err := tc.Handshake(); err != nil {
			c.Close()
			errCh <- err
			return
		}
		srvCurve = tc.ConnectionState().CurveID
		_, _ = tc.Write([]byte("pq-ok"))
		tc.Close()
		errCh <- nil
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, cliCfg)
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	cliCurve := tc.ConnectionState().CurveID
	buf := make([]byte, 16)
	n, err := tc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	tc.Close()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "pq-ok" {
		t.Fatalf("payload %q", buf[:n])
	}
	if cliCurve != tls.X25519MLKEM768 {
		t.Fatalf("client CurveID=%v want X25519MLKEM768", cliCurve)
	}
	if srvCurve != tls.X25519MLKEM768 {
		t.Fatalf("server CurveID=%v want X25519MLKEM768", srvCurve)
	}
}

func TestTLSClientNoSNI(t *testing.T) {
	cfg, err := tlsClientConfig(parse.Spec{
		Type: "OPENSSL",
		Options: []parse.Option{
			{Name: "openssl-no-sni"},
			{Name: "verify", Value: "0"},
		},
	}, "badssl.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "" {
		t.Fatalf("openssl-no-sni: ServerName=%q want empty", cfg.ServerName)
	}
}

func TestTLSClientSNIHost(t *testing.T) {
	cfg, err := tlsClientConfig(parse.Spec{
		Type: "OPENSSL",
		Options: []parse.Option{
			{Name: "openssl-snihost", Value: "sni.example", Has: true},
			{Name: "verify", Value: "0"},
		},
	}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "sni.example" {
		t.Fatalf("ServerName=%q", cfg.ServerName)
	}
}

func TestTLSServerVerifyUsesSystemRoots(t *testing.T) {
	cert, err := ephemeralSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := writeTLSCert(t, dir, "srv", cert)
	cfg, err := tlsServerConfig(parse.Spec{
		Type:   "OPENSSL-LISTEN",
		Params: []string{"443"},
		Options: []parse.Option{
			{Name: "cert", Value: certPath, Has: true},
			{Name: "verify", Value: "1", Has: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth=%v want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Fatal("ClientCAs is nil; want system or explicit pool")
	}
}

func TestTLSServerVerifyRejectsUntrustedClient(t *testing.T) {
	srv, err := ephemeralSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	cli, err := ephemeralSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dir := t.TempDir()
	srvPath := writeTLSCert(t, dir, "srv", srv)
	sCfg, err := tlsServerConfig(parse.Spec{
		Type: "OPENSSL-LISTEN",
		Options: []parse.Option{
			{Name: "cert", Value: srvPath, Has: true},
			{Name: "verify", Value: "1", Has: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		tc := tls.Server(c, sCfg)
		errCh <- tc.Handshake()
		_ = tc.Close()
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cli},
	})
	_ = tc.Handshake()
	_ = tc.Close()
	herr := <-errCh
	if herr == nil {
		t.Fatal("server accepted untrusted client cert")
	}
}

func TestLoadCAPath(t *testing.T) {
	ca, leaf, err := testCAAndLeaf("localhost")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	pool, err := loadCAPool(parse.Spec{Options: []parse.Option{{Name: "capath", Value: dir, Has: true}}})
	if err != nil {
		t.Fatal(err)
	}
	opts := x509.VerifyOptions{Roots: pool, DNSName: "localhost"}
	if _, err := leaf.Verify(opts); err != nil {
		t.Fatalf("capath verify: %v", err)
	}
}

func writeTLSCert(t *testing.T, dir, name string, cert tls.Certificate) string {
	t.Helper()
	if len(cert.Certificate) == 0 {
		t.Fatal("empty cert")
	}
	path := filepath.Join(dir, name+".pem")
	var b []byte
	for _, der := range cert.Certificate {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey); err == nil {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})...)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testCAAndLeaf(dns string) (*x509.Certificate, *x509.Certificate, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, err
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: dns},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{dns},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, nil, err
	}
	return caCert, leaf, nil
}
