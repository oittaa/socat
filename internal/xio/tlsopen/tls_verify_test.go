package tlsopen

import (
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testcert"
)

func TestVerifyPeerName(t *testing.T) {
	ca, roots := testRoots(t)
	for _, tc := range []struct {
		name  string
		chain [][]byte
		check string
		ok    bool
	}{
		{"SAN match", testChain(t, ca, "", x509.ExtKeyUsageServerAuth, "host.example"), "host.example", true},
		{"SAN mismatch", testChain(t, ca, "", x509.ExtKeyUsageServerAuth, "host.example"), "other.example", false},
		{"CN beside other SANs", testChain(t, ca, "other.example", x509.ExtKeyUsageServerAuth, "host.example"), "other.example", false},
		{"CN without SANs", testChain(t, ca, "host.example", x509.ExtKeyUsageServerAuth), "host.example", true},
		{"IP CN without SANs", testChain(t, ca, "127.0.0.1", x509.ExtKeyUsageServerAuth), "127.0.0.1", true},
		{"empty commonname", testChain(t, ca, "", x509.ExtKeyUsageServerAuth, "host.example"), "", true},
	} {
		if err := makeVerifyPeer(roots, tc.check)(tc.chain, nil); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

func TestVerifyPeerRejectsUntrustedChain(t *testing.T) {
	_, roots := testRoots(t)
	other, _ := testRoots(t)
	chain := testChain(t, other, "", x509.ExtKeyUsageServerAuth, "host.example")
	for _, name := range []string{"host.example", ""} {
		if makeVerifyPeer(roots, name)(chain, nil) == nil {
			t.Errorf("commonname %q: untrusted chain accepted", name)
		}
	}
}

func TestServerVerifyPeer(t *testing.T) {
	ca, roots := testRoots(t)
	other, _ := testRoots(t)
	for _, tc := range []struct {
		name  string
		chain [][]byte
		cn    string
		ok    bool
	}{
		{"trusted", testChain(t, ca, "alice", x509.ExtKeyUsageClientAuth), "", true},
		{"commonname match", testChain(t, ca, "alice", x509.ExtKeyUsageClientAuth), "alice", true},
		{"commonname mismatch", testChain(t, ca, "bob", x509.ExtKeyUsageClientAuth), "alice", false},
		{"untrusted CA", testChain(t, other, "alice", x509.ExtKeyUsageClientAuth), "", false},
		{"no certificate", nil, "", false},
	} {
		if err := makeServerVerifyPeer(roots, tc.cn)(tc.chain, nil); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

// crypto/tls skips VerifyPeerCertificate on resumption; VerifyConnection
// must still reject a peer with the wrong name.
func TestTLSClientConfigChecksResumedPeer(t *testing.T) {
	ca, _ := testRoots(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := testcert.WriteCertPEM(caFile, ca.DER); err != nil {
		t.Fatal(err)
	}
	cfg, err := tlsClientConfig(mustAddr(t, parse.Spec{
		Type:    "TLS",
		Params:  []string{"other.example", "443"},
		Options: []parse.Option{{Name: "cafile", Value: caFile, Has: true}},
	}), "other.example")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(testChain(t, ca, "", x509.ExtKeyUsageServerAuth, "host.example")[0])
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VerifyConnection == nil || cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}) == nil {
		t.Fatal("resumed session accepted a certificate for another name")
	}
}

func testRoots(t *testing.T) (*testcert.Authority, *x509.CertPool) {
	t.Helper()
	ca, err := testcert.NewAuthority("test CA")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	return ca, roots
}

func testChain(t *testing.T, ca *testcert.Authority, cn string, usage x509.ExtKeyUsage, dns ...string) [][]byte {
	t.Helper()
	leaf, err := ca.Leaf(cn, []x509.ExtKeyUsage{usage}, nil, dns)
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{leaf.DER}
}
