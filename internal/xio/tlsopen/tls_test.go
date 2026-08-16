package tlsopen

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
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

func TestTLSClientEmptyCommonNameKeepsDialSNI(t *testing.T) {
	cfg, err := tlsClientConfig(parse.Spec{
		Type: "TLS",
		Options: []parse.Option{
			{Name: "commonname", Value: "", Has: true},
			{Name: "verify", Value: "0"},
		},
	}, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "example.com" {
		t.Fatalf("ServerName=%q want example.com", cfg.ServerName)
	}
}

func TestTLSClientNoSNI(t *testing.T) {
	cfg, err := tlsClientConfig(parse.Spec{
		Type: "TLS",
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

func TestTLSServerConfigRequiresCert(t *testing.T) {
	_, err := tlsServerConfig(parse.Spec{Type: "TLS-LISTEN", Params: []string{"443"}})
	if err == nil {
		t.Fatal("expected error without cert=")
	}
	if !strings.Contains(err.Error(), "cert") {
		t.Fatalf("error %q should mention cert", err)
	}
}

func TestTLSClientSNIHost(t *testing.T) {
	cfg, err := tlsClientConfig(parse.Spec{
		Type: "TLS",
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
		Type:   "TLS-LISTEN",
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
		Type: "TLS-LISTEN",
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

func TestCommonNameOption(t *testing.T) {
	unset, err := parse.ParseSpec("TLS:127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	if name, set := commonNameOption(unset); set || name != "" {
		t.Fatalf("unset: name=%q set=%v", name, set)
	}

	empty, err := parse.ParseSpec("TLS:127.0.0.1:443,commonname=")
	if err != nil {
		t.Fatal(err)
	}
	if name, set := commonNameOption(empty); !set || name != "" {
		t.Fatalf("empty: name=%q set=%v", name, set)
	}

	alias, err := parse.ParseSpec("TLS:127.0.0.1:443,openssl-commonname=")
	if err != nil {
		t.Fatal(err)
	}
	if name, set := commonNameOption(alias); !set || name != "" {
		t.Fatalf("openssl-commonname=: name=%q set=%v", name, set)
	}

	named, err := parse.ParseSpec("TLS:127.0.0.1:443,commonname=localhost")
	if err != nil {
		t.Fatal(err)
	}
	if name, set := commonNameOption(named); !set || name != "localhost" {
		t.Fatalf("named: name=%q set=%v", name, set)
	}
}

func TestTLSClientCommonNameCheck(t *testing.T) {
	// Cert is for DNS:localhost only. Dial target is 127.0.0.1.
	// Classic: no commonname → name check fails; commonname=localhost → pass;
	// empty commonname= → skip name check, still verify the CA.
	ca, leaf, leafKey, err := testCAAndLeafKey("localhost")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	srvCert := tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: leafKey}

	cases := []struct {
		name    string
		opts    []parse.Option
		wantErr bool
	}{
		{
			name: "unset-checks-dial-host",
			opts: []parse.Option{
				{Name: "verify", Value: "1", Has: true},
				{Name: "cafile", Value: caPath, Has: true},
			},
			wantErr: true,
		},
		{
			name: "commonname-localhost",
			opts: []parse.Option{
				{Name: "verify", Value: "1", Has: true},
				{Name: "cafile", Value: caPath, Has: true},
				{Name: "commonname", Value: "localhost", Has: true},
			},
		},
		{
			name: "empty-commonname-skips-name",
			opts: []parse.Option{
				{Name: "verify", Value: "1", Has: true},
				{Name: "cafile", Value: caPath, Has: true},
				{Name: "commonname", Value: "", Has: true},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := handshakeClientToLocal(t, srvCert, parse.Spec{Type: "TLS", Options: tc.opts}, "127.0.0.1")
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected name-check failure")
				}
				return
			}
			if err != nil {
				t.Fatalf("handshake: %v", err)
			}
		})
	}
}

func TestTLSClientEmptyCommonNameStillVerifiesTrust(t *testing.T) {
	// Empty commonname= must not become verify=0: an untrusted leaf still fails.
	leaf, err := ephemeralSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	ca, _, err := testCAAndLeaf("other")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	err = handshakeClientToLocal(t, leaf, parse.Spec{
		Type: "TLS",
		Options: []parse.Option{
			{Name: "verify", Value: "1", Has: true},
			{Name: "cafile", Value: caPath, Has: true},
			{Name: "commonname", Value: "", Has: true},
		},
	}, "127.0.0.1")
	if err == nil {
		t.Fatal("expected trust failure with empty commonname=")
	}
}

func handshakeClientToLocal(t *testing.T, srvCert tls.Certificate, spec parse.Spec, dialName string) error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{srvCert}})
		errCh <- tc.Handshake()
		_ = tc.Close()
	}()
	cfg, err := tlsClientConfig(spec, dialName)
	if err != nil {
		return err
	}
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	cli := tls.Client(raw, cfg)
	herr := cli.Handshake()
	_ = cli.Close()
	_ = <-errCh
	return herr
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
	ca, leaf, _, err := testCAAndLeafKey(dns)
	return ca, leaf, err
}

func testCAAndLeafKey(dns string) (*x509.Certificate, *x509.Certificate, ed25519.PrivateKey, error) {
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
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
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPub, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, nil, err
	}
	leafPub, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
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
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, leafPub, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, nil, nil, err
	}
	return caCert, leaf, leafKey, nil
}
