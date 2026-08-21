// TLS peer verification: trust chains, name checks, and CN fallback gating.
package tlsopen

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func verifyEnabled(s parse.Spec) bool {
	// Classic default verify=1; verify=0 disables peer verification.
	// Bare "verify" without value is true (flag).
	if !s.HasOption("verify") {
		return true
	}
	return s.BoolOption("verify")
}

// commonNameOption returns openssl-commonname / commonname when the option
// is present with an explicit value, including the empty string.
// Classic: unset → check the dial host; commonname= (empty) → skip the name
// check; commonname=foo → check foo. verify=1 still checks trust.
func commonNameOption(s parse.Spec) (name string, set bool) {
	o, ok := s.OptionNamed("commonname")
	if !ok || !o.Has {
		return "", false
	}
	return o.Value, true
}

// attachPeerVerify sets both VerifyPeerCertificate and VerifyConnection.
// crypto/tls skips VerifyPeerCertificate on session resume; VerifyConnection
// still runs, so a resumed session cannot skip the name/trust check.
func attachPeerVerify(cfg *tls.Config, fn func([][]byte, [][]*x509.Certificate) error) {
	if cfg == nil || fn == nil {
		return
	}
	cfg.VerifyPeerCertificate = fn
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		raws := make([][]byte, len(cs.PeerCertificates))
		for i, c := range cs.PeerCertificates {
			raws[i] = c.Raw
		}
		return fn(raws, nil)
	}
}

// makeServerVerifyPeer checks client certificate chain and optional commonname.
func makeServerVerifyPeer(roots *x509.CertPool, cnWant string, doVerify bool, prev func([][]byte, [][]*x509.Certificate) error) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
		if prev != nil {
			if err := prev(rawCerts, chains); err != nil {
				return err
			}
		}
		if len(rawCerts) == 0 {
			if cnWant != "" || doVerify {
				return fmt.Errorf("tls: no client certificate")
			}
			return nil
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		if doVerify {
			if roots == nil {
				return fmt.Errorf("tls: no CA roots for client certificate")
			}
			opts := x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
			inter := x509.NewCertPool()
			for i := 1; i < len(rawCerts); i++ {
				if c, e := x509.ParseCertificate(rawCerts[i]); e == nil {
					inter.AddCert(c)
				}
			}
			opts.Intermediates = inter
			if _, err := leaf.Verify(opts); err != nil {
				return err
			}
		}
		if cnWant != "" {
			if !cnMatches(leaf, cnWant) {
				return fmt.Errorf("tls: client commonName %q does not match %q", leaf.Subject.CommonName, cnWant)
			}
		}
		return nil
	}
}

// sniName is the TLS ServerName. Prefer a non-IP check name (commonname=),
// else the dial host when that is not an IP.
func sniName(checkName, dialHost string) string {
	if checkName != "" {
		if ip := net.ParseIP(checkName); ip == nil {
			return checkName
		}
	}
	if dialHost != "" {
		if ip := net.ParseIP(dialHost); ip == nil {
			return dialHost
		}
	}
	return ""
}

// makeVerifyPeer verifies the leaf against roots and checks name via SAN or CN.
// Empty checkName skips the name check (classic empty commonname=).
// Classic test certs often lack SANs; we still allow CN match for the check name.
func makeVerifyPeer(roots *x509.CertPool, checkName string) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("tls: no peer certificates")
		}
		certs := make([]*x509.Certificate, 0, len(rawCerts))
		for _, raw := range rawCerts {
			c, err := x509.ParseCertificate(raw)
			if err != nil {
				return err
			}
			certs = append(certs, c)
		}
		leaf := certs[0]
		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: x509.NewCertPool(),
		}
		for _, c := range certs[1:] {
			opts.Intermediates.AddCert(c)
		}
		if roots == nil {
			sys, err := x509.SystemCertPool()
			if err != nil {
				return err
			}
			opts.Roots = sys
		}
		if _, err := leaf.Verify(opts); err != nil {
			return err
		}
		if checkName == "" {
			// Classic: empty commonname / empty peername skips the name check.
			return nil
		}
		// RFC 6125 name check (Go VerifyHostname). Classic OPENSSL uses strcmp
		// plus a looser *.domain rule; we keep the Go rules.
		if err := leaf.VerifyHostname(checkName); err == nil {
			return nil
		}
		// RFC 6125 §6.4.4 / OpenSSL X509_check_host parity: the CN fallback
		// applies only when the certificate carries no subjectAltName entries
		// at all (classic test certs). A certificate with SANs must match via
		// its SANs; a matching CN beside non-matching SANs must fail.
		if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 && cnMatches(leaf, checkName) {
			return nil
		}
		// Without a matching SAN/CN, fail (OPENSSL_CN_CLIENT_SECURITY:
		// connect 127.0.0.1 without commonname must fail).
		return fmt.Errorf("tls: certificate hostname mismatch (CN=%q name=%q)", leaf.Subject.CommonName, checkName)
	}
}

// cnMatches compares the certificate subject CN with want (classic strcmp on
// the CN). Only reached when the certificate has no SANs; see makeVerifyPeer.
func cnMatches(leaf *x509.Certificate, want string) bool {
	if leaf == nil || want == "" {
		return false
	}
	// OPENSSLTCP6_*: classic test certs use CN="[::1]" while dial name is ::1.
	want = xio.StripBrackets(want)
	cn := xio.StripBrackets(leaf.Subject.CommonName)
	return strings.EqualFold(cn, want)
}
