// TLS session metadata capture: negotiated parameters and peer-certificate
// fields exported into the child environment as SOCAT_TLS_* / SOCAT_OPENSSL_*.
package xio

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"strings"
	"time"
)

// RememberTLSPeer records negotiated TLS and peer-certificate metadata. The
// child environment exposes preferred SOCAT_TLS_* names and SOCAT_OPENSSL_*
// compatibility aliases.
func RememberTLSPeer(g *Global, c net.Conn, timeout time.Duration) error {
	if c == nil {
		return nil
	}
	if p, ok := c.(interface {
		TLSConnectionState() (tls.ConnectionState, bool)
	}); ok {
		if st, ok := p.TLSConnectionState(); ok {
			rememberTLSState(g, st)
			return nil
		}
	}
	tc, ok := c.(*tls.Conn)
	if !ok {
		// tls.NewListener returns *tls.Conn; still handle wrappers.
		if u, ok := c.(interface{ NetConn() net.Conn }); ok {
			if tc2, ok := u.NetConn().(*tls.Conn); ok {
				tc = tc2
			} else {
				return nil
			}
		} else {
			return nil
		}
	}
	if err := WithHandshakeDeadline(tc, timeout, tc.Handshake); err != nil {
		return err
	}
	if g != nil {
		rememberTLSState(g, tc.ConnectionState())
	}
	return nil
}

func rememberTLSState(g *Global, st tls.ConnectionState) {
	if g == nil {
		return
	}
	g.TLSVars = make(map[string]string)
	if st.Version != 0 {
		g.TLSVars["PROTO_VERSION"] = tlsProtocolVersion(st.Version)
	}
	if st.CipherSuite != 0 {
		g.TLSVars["CIPHER"] = tls.CipherSuiteName(st.CipherSuite)
	}
	if len(st.PeerCertificates) == 0 {
		return
	}
	leaf := st.PeerCertificates[0]
	// Layout: "C = XY, CN = localhost, O = dest-unreach, OU = socat, L = Lunar Base"
	g.TLSVars["X509_SUBJECT"] = FormatTLSName(leaf.Subject)
	g.TLSVars["X509_ISSUER"] = FormatTLSName(leaf.Issuer)
	for name, value := range tlsSubjectFields(leaf.Subject) {
		g.TLSVars["X509_"+name] = value
	}
	if len(leaf.DNSNames) > 0 {
		value := strings.Join(leaf.DNSNames, " // ")
		g.TLSVars["X509V3_SUBJECTALTNAME_DNS"] = value
		// Older manuals documented this shortened spelling.
		g.TLSVars["X509V3_DNS"] = value
	}
	if len(leaf.IPAddresses) > 0 {
		values := make([]string, 0, len(leaf.IPAddresses))
		for _, ip := range leaf.IPAddresses {
			values = append(values, ip.String())
		}
		g.TLSVars["X509V3_SUBJECTALTNAME_IPADD"] = strings.Join(values, " // ")
	}
}

func tlsProtocolVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLSv1"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return tls.VersionName(version)
	}
}

func tlsSubjectFields(n pkix.Name) map[string]string {
	fields := make(map[string]string)
	attributeValues := make(map[string][]string)
	attributeNames := map[string]string{
		"2.5.4.3":                    "COMMONNAME",
		"2.5.4.4":                    "SURNAME",
		"2.5.4.5":                    "SERIALNUMBER",
		"2.5.4.6":                    "COUNTRYNAME",
		"2.5.4.7":                    "LOCALITYNAME",
		"2.5.4.8":                    "STATEORPROVINCENAME",
		"2.5.4.9":                    "STREETADDRESS",
		"2.5.4.10":                   "ORGANIZATIONNAME",
		"2.5.4.11":                   "ORGANIZATIONALUNITNAME",
		"2.5.4.12":                   "TITLE",
		"2.5.4.17":                   "POSTALCODE",
		"2.5.4.42":                   "GIVENNAME",
		"1.2.840.113549.1.9.1":       "EMAILADDRESS",
		"0.9.2342.19200300.100.1.1":  "USERID",
		"0.9.2342.19200300.100.1.25": "DOMAINCOMPONENT",
	}
	for _, attribute := range n.Names {
		name := attributeNames[attribute.Type.String()]
		if name == "" {
			name = "UNDEF"
		}
		attributeValues[name] = append(attributeValues[name], fmt.Sprint(attribute.Value))
	}
	for name, values := range attributeValues {
		fields[name] = strings.Join(values, " // ")
	}
	add := func(name string, values []string) {
		if len(values) > 0 && fields[name] == "" {
			fields[name] = strings.Join(values, " // ")
		}
	}
	if n.CommonName != "" && fields["COMMONNAME"] == "" {
		fields["COMMONNAME"] = n.CommonName
	}
	add("COUNTRYNAME", n.Country)
	add("LOCALITYNAME", n.Locality)
	add("STATEORPROVINCENAME", n.Province)
	add("ORGANIZATIONNAME", n.Organization)
	add("ORGANIZATIONALUNITNAME", n.OrganizationalUnit)
	add("STREETADDRESS", n.StreetAddress)
	add("POSTALCODE", n.PostalCode)
	if n.SerialNumber != "" && fields["SERIALNUMBER"] == "" {
		fields["SERIALNUMBER"] = n.SerialNumber
	}
	return fields
}

// FormatTLSName matches SOCAT_OPENSSL_X509_SUBJECT / ISSUER layout.
func FormatTLSName(n pkix.Name) string {
	// Order: C, CN, O, OU, L
	var parts []string
	if len(n.Country) > 0 {
		parts = append(parts, "C = "+n.Country[0])
	}
	if n.CommonName != "" {
		parts = append(parts, "CN = "+n.CommonName)
	}
	if len(n.Organization) > 0 {
		parts = append(parts, "O = "+n.Organization[0])
	}
	if len(n.OrganizationalUnit) > 0 {
		parts = append(parts, "OU = "+n.OrganizationalUnit[0])
	}
	if len(n.Locality) > 0 {
		parts = append(parts, "L = "+n.Locality[0])
	}
	return strings.Join(parts, ", ")
}
