package tlsopen

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testcert"
)

func TestTLSClientEmptyCommonNameKeepsDialSNI(t *testing.T) {
	cfg, err := tlsClientConfig(mustAddr(t, parse.Spec{
		Type: "TLS",
		Options: []parse.Option{
			{Name: "commonname", Value: "", Has: true},
			{Name: "verify", Value: "0"},
		},
	}), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "example.com" {
		t.Fatalf("ServerName=%q want example.com", cfg.ServerName)
	}
}

func TestTLSClientNoSNI(t *testing.T) {
	cfg, err := tlsClientConfig(mustAddr(t, parse.Spec{
		Type: "TLS",
		Options: []parse.Option{
			{Name: "openssl-no-sni"},
			{Name: "verify", Value: "0"},
		},
	}), "badssl.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "" {
		t.Fatalf("openssl-no-sni: ServerName=%q want empty", cfg.ServerName)
	}
}

func TestTLSServerConfigRequiresCert(t *testing.T) {
	_, err := tlsServerConfig(mustAddr(t, parse.Spec{Type: "TLS-LISTEN", Params: []string{"443"}}))
	if err == nil {
		t.Fatal("expected error without cert=")
	}
	if !strings.Contains(err.Error(), "cert") {
		t.Fatalf("error %q should mention cert", err)
	}
}

func TestTLSClientSNIHost(t *testing.T) {
	cfg, err := tlsClientConfig(mustAddr(t, parse.Spec{
		Type: "TLS",
		Options: []parse.Option{
			{Name: "openssl-snihost", Value: "sni.example", Has: true},
			{Name: "verify", Value: "0"},
		},
	}), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "sni.example" {
		t.Fatalf("ServerName=%q", cfg.ServerName)
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
	pool, err := loadCAPoolPaths("", dir)
	if err != nil {
		t.Fatal(err)
	}
	opts := x509.VerifyOptions{Roots: pool, DNSName: "localhost"}
	if _, err := leaf.Verify(opts); err != nil {
		t.Fatalf("capath verify: %v", err)
	}
}

func TestTLSCipherListCompatibility(t *testing.T) {
	spec, err := parse.ParseSpec("OPENSSL:localhost:443,cipher=ECDHE-ECDSA-AES256-GCM-SHA384")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := tlsClientConfig(mustAddr(t, spec), "localhost")
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}
	if !slices.Equal(cfg.CipherSuites, want) {
		t.Fatalf("CipherSuites=%#v want %#v", cfg.CipherSuites, want)
	}
	if cfg.MaxVersion != 0 {
		t.Fatalf("cipher list must not disable TLS 1.3; MaxVersion=%#x", cfg.MaxVersion)
	}
}

func TestTLSProtocolVersionOptions(t *testing.T) {
	spec, err := parse.ParseSpec("TLS:localhost:443,min-version=TLSv1.1,openssl-max-proto-version=TLS1.3,verify=0")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := tlsClientConfig(mustAddr(t, spec), "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS11 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("protocol bounds=%#x..%#x", cfg.MinVersion, cfg.MaxVersion)
	}
}

func TestTLSProtocolVersionOptionsRejectInvalidBounds(t *testing.T) {
	for _, text := range []string{
		"TLS:localhost:443,min-version=DTLS1.2,verify=0",
		"TLS:localhost:443,min-version=TLS1.3,max-version=TLS1.2,verify=0",
	} {
		spec, err := parse.ParseSpec(text)
		if err != nil {
			t.Fatal(err)
		}
		config, err := tryAddr(spec)
		if err == nil {
			_, err = tlsClientConfig(config, "localhost")
		}
		if err == nil {
			t.Fatalf("tlsClientConfig(%q) succeeded", text)
		}
	}
}

func TestTLSCipherListRejectsUnsupportedPolicy(t *testing.T) {
	for _, value := range []string{"aNULL", "DEFAULT", "TLS_AES_128_GCM_SHA256"} {
		spec, err := parse.ParseSpec("TLS:localhost:443,ciphers=" + value)
		if err != nil {
			t.Fatal(err)
		}
		config, err := tryAddr(spec)
		if err == nil {
			_, err = tlsClientConfig(config, "localhost")
		}
		if err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Errorf("ciphers=%q error=%v", value, err)
		}
	}
}

func testCAAndLeaf(dns string) (*x509.Certificate, *x509.Certificate, error) {
	ca, leaf, _, err := testCAAndLeafKey(dns)
	return ca, leaf, err
}

func testCAAndLeafKey(dns string) (*x509.Certificate, *x509.Certificate, ed25519.PrivateKey, error) {
	return testCAAndLeafKeyUsage(dns, x509.ExtKeyUsageServerAuth)
}

// testCAAndLeafKeyUsage delegates to the shared testcert generators; the
// returned shapes keep the historical helper signature.
func testCAAndLeafKeyUsage(dns string, usage x509.ExtKeyUsage) (*x509.Certificate, *x509.Certificate, ed25519.PrivateKey, error) {
	a, err := testcert.NewAuthority("test-ca")
	if err != nil {
		return nil, nil, nil, err
	}
	l, err := a.Leaf(dns, []x509.ExtKeyUsage{usage}, nil, []string{dns})
	if err != nil {
		return nil, nil, nil, err
	}
	return a.Cert, l.Cert, l.Key, nil
}
