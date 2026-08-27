package tlsopen

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testcert"
)

func TestTLSPublicCatalogAliasesLastOptionWins(t *testing.T) {
	ca, err := testcert.NewAuthority("testca")
	if err != nil {
		t.Fatal(err)
	}
	first, err := ca.Leaf("first.example", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil, []string{"first.example"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := ca.Leaf("second.example", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil, []string{"second.example"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	firstPath := writeTLSCert(t, dir, "first", first.TLS())
	secondPath := writeTLSCert(t, dir, "second", second.TLS())

	spec, err := parse.ParseSpec(fmt.Sprintf(
		"TLS-LISTEN:443,verify=0,cert=%s,openssl-certificate=%s", firstPath, secondPath))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := tlsServerConfig(spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates=%d", len(cfg.Certificates))
	}
	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "second.example" {
		t.Fatalf("loaded CN=%q want second.example (last-option-wins)", leaf.Subject.CommonName)
	}
}

func TestTLSPublicCatalogAliasesLoadCertKeyCAVerify(t *testing.T) {
	ca, err := testcert.NewAuthority("testca")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf("localhost", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, nil, []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath, err := leaf.WriteCertAndKey(dir, "peer")
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, "ca.pem")
	if err := testcert.WriteCertPEM(caPath, ca.DER); err != nil {
		t.Fatal(err)
	}

	t.Run("openssl-certificate-and-key", func(t *testing.T) {
		spec, err := parse.ParseSpec(fmt.Sprintf(
			"TLS-LISTEN:443,verify=0,openssl-certificate=%s,openssl-key=%s", certPath, keyPath))
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := tlsServerConfig(spec)
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.Certificates) != 1 {
			t.Fatalf("Certificates=%d", len(cfg.Certificates))
		}
		got, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if got.Subject.CommonName != "localhost" {
			t.Fatalf("CN=%q", got.Subject.CommonName)
		}
	})

	t.Run("certificate-nickname", func(t *testing.T) {
		spec, err := parse.ParseSpec(fmt.Sprintf(
			"OPENSSL-LISTEN:443,verify=0,certificate=%s,openssl-key=%s", certPath, keyPath))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tlsServerConfig(spec); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("openssl-cafile-and-verify", func(t *testing.T) {
		spec, err := parse.ParseSpec(fmt.Sprintf(
			"TLS:127.0.0.1:443,openssl-verify=1,openssl-cafile=%s,cn=localhost", caPath))
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := tlsClientConfig(spec, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.VerifyPeerCertificate == nil || cfg.RootCAs == nil {
			t.Fatal("openssl-verify=1 + openssl-cafile did not install trust")
		}
	})

	t.Run("openssl-verify-last-wins-off", func(t *testing.T) {
		spec, err := parse.ParseSpec(fmt.Sprintf(
			"TLS:127.0.0.1:443,verify=1,openssl-cafile=%s,openssl-verify=0", caPath))
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := tlsClientConfig(spec, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.InsecureSkipVerify || cfg.VerifyPeerCertificate != nil {
			t.Fatal("openssl-verify=0 must win over verify=1")
		}
	})
}

func TestTLSPublicCatalogAliasesSNICipherProto(t *testing.T) {
	t.Run("no-sni", func(t *testing.T) {
		spec, err := parse.ParseSpec("TLS:badssl.com:443,verify=0,no-sni")
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := tlsClientConfig(spec, "badssl.com")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ServerName != "" {
			t.Fatalf("no-sni: ServerName=%q want empty", cfg.ServerName)
		}
	})

	t.Run("cn", func(t *testing.T) {
		spec, err := parse.ParseSpec("TLS:127.0.0.1:443,verify=0,cn=sni.example")
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := tlsClientConfig(spec, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ServerName != "sni.example" {
			t.Fatalf("cn: ServerName=%q", cfg.ServerName)
		}
	})

	t.Run("cipherlist", func(t *testing.T) {
		spec, err := parse.ParseSpec("OPENSSL:localhost:443,cipherlist=ECDHE-ECDSA-AES256-GCM-SHA384")
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := tlsClientConfig(spec, "localhost")
		if err != nil {
			t.Fatal(err)
		}
		want := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}
		if !slices.Equal(cfg.CipherSuites, want) {
			t.Fatalf("CipherSuites=%#v want %#v", cfg.CipherSuites, want)
		}
	})

	t.Run("min-max-proto-version", func(t *testing.T) {
		spec, err := parse.ParseSpec("TLS:localhost:443,verify=0,min-proto-version=TLS1.2,max-proto-version=TLS1.3")
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := tlsClientConfig(spec, "localhost")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.MinVersion != tls.VersionTLS12 || cfg.MaxVersion != tls.VersionTLS13 {
			t.Fatalf("protocol bounds=%#x..%#x", cfg.MinVersion, cfg.MaxVersion)
		}
	})

	t.Run("min-proto-version-last-wins", func(t *testing.T) {
		spec, err := parse.ParseSpec("TLS:localhost:443,verify=0,min-version=TLS1.0,min-proto-version=TLS1.2")
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := tlsClientConfig(spec, "localhost")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Fatalf("MinVersion=%#x want TLS1.2", cfg.MinVersion)
		}
	})
}

func TestLoadCAPoolOpenSSLCafileAlias(t *testing.T) {
	ca, leaf, err := testCAAndLeaf("localhost")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("TLS:localhost:443,openssl-cafile=" + caPath)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := loadCAPool(spec)
	if err != nil {
		t.Fatal(err)
	}
	opts := x509.VerifyOptions{Roots: pool, DNSName: "localhost"}
	if _, err := leaf.Verify(opts); err != nil {
		t.Fatalf("openssl-cafile verify: %v", err)
	}
}
