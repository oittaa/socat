package xio

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func environMap(env []string) map[string]string {
	got := make(map[string]string)
	for _, entry := range env {
		i := strings.IndexByte(entry, '=')
		if i >= 0 {
			got[entry[:i]] = entry[i+1:]
		}
	}
	return got
}

func TestChildEnvironOverlaysSession(t *testing.T) {
	t.Setenv("SOCAT_PEERADDR", "stale")
	g := &Global{SockAddr: "10.0.0.1", SockPort: "1", PeerAddr: "10.0.0.2", PeerPort: "2", Progname: "socat"}
	got := environMap(childEnviron(g))
	if got["SOCAT_PEERADDR"] != "10.0.0.2" {
		t.Fatalf("SOCAT_PEERADDR=%q", got["SOCAT_PEERADDR"])
	}
	if got["SOCAT_SOCKADDR"] != "10.0.0.1" {
		t.Fatalf("SOCAT_SOCKADDR=%q", got["SOCAT_SOCKADDR"])
	}
	if got["SOCAT_VERSION"] == "" {
		t.Fatal("SOCAT_VERSION is empty")
	}
	pid := strconv.Itoa(os.Getpid())
	if got["SOCAT_PID"] != pid || got["SOCAT_PPID"] != pid {
		t.Fatalf("PID=%q PPID=%q want %q", got["SOCAT_PID"], got["SOCAT_PPID"], pid)
	}
}

func TestSessionEnvironUsesPrognameAndSocatCompatibilityNames(t *testing.T) {
	g := &Global{Progname: "relay", SessionVars: map[string]string{"TIMESTAMP": "now"}}
	got := environMap(sessionEnv(g))
	for _, name := range []string{"SOCAT_TIMESTAMP", "RELAY_TIMESTAMP", "SOCAT_VERSION", "RELAY_VERSION"} {
		if got[name] == "" {
			t.Errorf("%s is empty", name)
		}
	}
}

func TestTLSEnvironUsesTLSNamesAndOpenSSLAliases(t *testing.T) {
	t.Setenv("SOCAT_OPENSSL_X509_STALE", "must-not-leak")
	t.Setenv("SOCAT_TLS_X509_STALE", "must-not-leak")
	g := &Global{Progname: "relay"}
	rememberTLSState(g, tls.ConnectionState{
		Version:     tls.VersionTLS13,
		CipherSuite: tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates: []*x509.Certificate{{
			Subject: pkix.Name{
				CommonName:         "peer.example",
				Country:            []string{"FI"},
				Organization:       []string{"One", "Two"},
				OrganizationalUnit: []string{"Relay"},
				Names: []pkix.AttributeTypeAndValue{
					{Type: []int{1, 2, 840, 113549, 1, 9, 1}, Value: "peer@example.test"},
				},
			},
			Issuer:      pkix.Name{CommonName: "Test CA"},
			DNSNames:    []string{"peer.example", "alt.example"},
			IPAddresses: []net.IP{net.ParseIP("192.0.2.1")},
		}},
	})
	got := environMap(childEnviron(g))
	pairs := [][2]string{
		{"SOCAT_TLS_PROTO_VERSION", "SOCAT_OPENSSL_PROTO_VERSION"},
		{"SOCAT_TLS_CIPHER", "SOCAT_OPENSSL_CIPHER"},
		{"SOCAT_TLS_X509_SUBJECT", "SOCAT_OPENSSL_X509_SUBJECT"},
		{"SOCAT_TLS_X509_COMMONNAME", "SOCAT_OPENSSL_X509_COMMONNAME"},
		{"SOCAT_TLS_X509V3_SUBJECTALTNAME_DNS", "SOCAT_OPENSSL_X509V3_SUBJECTALTNAME_DNS"},
		{"SOCAT_TLS_X509V3_SUBJECTALTNAME_IPADD", "SOCAT_OPENSSL_X509V3_SUBJECTALTNAME_IPADD"},
		{"RELAY_TLS_X509_SUBJECT", "RELAY_OPENSSL_X509_SUBJECT"},
	}
	for _, pair := range pairs {
		if got[pair[0]] == "" || got[pair[0]] != got[pair[1]] {
			t.Errorf("%s=%q %s=%q", pair[0], got[pair[0]], pair[1], got[pair[1]])
		}
	}
	if got["SOCAT_TLS_PROTO_VERSION"] != "TLSv1.3" {
		t.Errorf("protocol=%q", got["SOCAT_TLS_PROTO_VERSION"])
	}
	if got["SOCAT_TLS_X509_ORGANIZATIONNAME"] != "One // Two" {
		t.Errorf("organization=%q", got["SOCAT_TLS_X509_ORGANIZATIONNAME"])
	}
	if got["SOCAT_TLS_X509_EMAILADDRESS"] != "peer@example.test" {
		t.Errorf("emailAddress=%q", got["SOCAT_TLS_X509_EMAILADDRESS"])
	}
	if got["SOCAT_TLS_X509V3_DNS"] != "peer.example // alt.example" {
		t.Errorf("documented DNS alias=%q", got["SOCAT_TLS_X509V3_DNS"])
	}
	if _, ok := got["SOCAT_OPENSSL_X509_STALE"]; ok {
		t.Error("stale SOCAT_OPENSSL_* variable leaked into TLS child")
	}
	if _, ok := got["SOCAT_TLS_X509_STALE"]; ok {
		t.Error("stale SOCAT_TLS_* variable leaked into TLS child")
	}
}

func TestSniffEnvFromSession(t *testing.T) {
	g := &Global{PeerAddr: "192.0.2.1", PeerPort: "9"}
	v, ok := sniffEnvValue(g, "SOCAT_PEERADDR")
	if !ok || v != "192.0.2.1" {
		t.Fatalf("got %q %v", v, ok)
	}
	path, err := expandSniffPath("/tmp/$SOCAT_PEERADDR.log", "socat", time.Now(), g)
	if err != nil {
		t.Fatal(err)
	}
	if path != "/tmp/192.0.2.1.log" {
		t.Fatalf("path=%q", path)
	}
}

func TestForkSessionSharesStatsFlag(t *testing.T) {
	g := &Global{
		PeerAddr:    "parent",
		TLSVars:     map[string]string{"CIPHER": "parent"},
		SessionVars: map[string]string{"TIMESTAMP": "parent"},
	}
	g.EnsureStatsFlag()
	a := g.forkSession()
	b := g.forkSession()
	a.PeerAddr = "child-a"
	a.TLSVars["CIPHER"] = "child-a"
	a.SessionVars["TIMESTAMP"] = "child-a"
	if g.PeerAddr != "parent" || b.PeerAddr != "parent" {
		t.Fatalf("peer fields must be per-child: parent=%q b=%q", g.PeerAddr, b.PeerAddr)
	}
	if g.TLSVars["CIPHER"] != "parent" || b.TLSVars["CIPHER"] != "parent" ||
		g.SessionVars["TIMESTAMP"] != "parent" || b.SessionVars["TIMESTAMP"] != "parent" {
		t.Fatal("environment maps must be copied per child")
	}
	a.markStatsPrinted()
	if !b.statsAlreadyPrinted() || !g.statsAlreadyPrinted() {
		t.Fatal("stats flag must be shared so --statistics prints once")
	}
}

func TestPreferredResolveVersionFromEnvironment(t *testing.T) {
	t.Setenv("SOCAT_PREFERRED_RESOLVE_IP", "6")
	if got := preferredResolveVersion(&Global{}); got != IPv6 {
		t.Fatalf("env=6 got %v", got)
	}
	if got := preferredResolveVersion(&Global{IPVersion: IPv4}); got != IPv4 {
		t.Fatalf("explicit -4 must win, got %v", got)
	}
	t.Setenv("SOCAT_PREFERRED_RESOLVE_IP", "0")
	if got := preferredResolveVersion(&Global{}); got != IPvAny {
		t.Fatalf("env=0 got %v", got)
	}
}

func TestEnvironmentWaitDuration(t *testing.T) {
	if got := environmentWaitDuration("2"); got != 2*time.Second {
		t.Fatalf("got %s", got)
	}
	for _, value := range []string{"", "invalid", "0", "-1"} {
		if got := environmentWaitDuration(value); got != 0 {
			t.Errorf("%q got %s", value, got)
		}
	}
}
