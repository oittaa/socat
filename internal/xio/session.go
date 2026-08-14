package xio

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

// RememberAddrs fills SOCAT_* environment fields on g from a live connection.
// Also exports classic process env used by -r/-R path expansion ($SERVER0_PEERADDR).
func RememberAddrs(g *Global, c net.Conn) {
	if g == nil || c == nil {
		return
	}
	if la := c.LocalAddr(); la != nil {
		host, port, err := net.SplitHostPort(la.String())
		if err == nil {
			g.SockAddr = FormatSocatAddr(host)
			g.SockPort = port
		} else {
			g.SockAddr = la.String()
		}
	}
	if ra := c.RemoteAddr(); ra != nil {
		host, port, err := net.SplitHostPort(ra.String())
		if err == nil {
			g.PeerAddr = FormatSocatAddr(host)
			g.PeerPort = port
		} else {
			g.PeerAddr = ra.String()
		}
	}
	// Session fields stay on g. EXEC children get them via childEnviron.
	// Do not os.Setenv: fork goroutines would race on process environment.
}

// sessionEnv returns classic SOCAT_* / PROGNAME_* values from this session.
func sessionEnv(g *Global) []string {
	if g == nil {
		return nil
	}
	prog := g.Progname
	if prog == "" {
		prog = "socat"
	}
	up := strings.ToUpper(prog)
	out := []string{
		"SOCAT_SOCKADDR=" + g.SockAddr,
		"SOCAT_PEERADDR=" + g.PeerAddr,
		"SOCAT_SOCKPORT=" + g.SockPort,
		"SOCAT_PEERPORT=" + g.PeerPort,
		up + "_SOCKADDR=" + g.SockAddr,
		up + "_PEERADDR=" + g.PeerAddr,
		up + "_SOCKPORT=" + g.SockPort,
		up + "_PEERPORT=" + g.PeerPort,
	}
	if g.TLSPeerSubject != "" {
		out = append(out,
			"SOCAT_OPENSSL_X509_SUBJECT="+g.TLSPeerSubject,
			"SOCAT_OPENSSL_X509_ISSUER="+g.TLSPeerIssuer,
			"SOCAT_OPENSSL_X509_COMMONNAME="+g.TLSPeerCommonName,
			"SOCAT_OPENSSL_X509_COUNTRYNAME="+g.TLSPeerCountry,
			"SOCAT_OPENSSL_X509_LOCALITYNAME="+g.TLSPeerLocality,
			"SOCAT_OPENSSL_X509_ORGANIZATIONNAME="+g.TLSPeerOrg,
			"SOCAT_OPENSSL_X509_ORGANIZATIONALUNITNAME="+g.TLSPeerOrgUnit,
		)
	}
	return out
}

// childEnviron copies the process environment and overlays this session's
// SOCAT_* keys (last key wins). Used for EXEC/SYSTEM/SHELL so fork children
// do not share process-wide Setenv.
func childEnviron(g *Global) []string {
	extra := sessionEnv(g)
	if len(extra) == 0 {
		return os.Environ()
	}
	drop := make(map[string]struct{}, len(extra))
	for _, e := range extra {
		if i := strings.IndexByte(e, '='); i > 0 {
			drop[e[:i]] = struct{}{}
		}
	}
	base := os.Environ()
	out := make([]string, 0, len(base)+len(extra))
	for _, e := range base {
		k := e
		if i := strings.IndexByte(e, '='); i > 0 {
			k = e[:i]
		}
		if _, skip := drop[k]; skip {
			continue
		}
		out = append(out, e)
	}
	return append(out, extra...)
}

// sniffEnvValue resolves -r/-R $NAME from this session (not process getenv).
func sniffEnvValue(g *Global, name string) (string, bool) {
	if g == nil {
		return "", false
	}
	prog := g.Progname
	if prog == "" {
		prog = "socat"
	}
	up := strings.ToUpper(prog)
	switch name {
	case "SOCAT_SOCKADDR", up + "_SOCKADDR", "SOCKADDR":
		return g.SockAddr, true
	case "SOCAT_PEERADDR", up + "_PEERADDR", "PEERADDR":
		return g.PeerAddr, true
	case "SOCAT_SOCKPORT", up + "_SOCKPORT", "SOCKPORT":
		return g.SockPort, true
	case "SOCAT_PEERPORT", up + "_PEERPORT", "PEERPORT":
		return g.PeerPort, true
	}
	return "", false
}

// ExportSocatEnv is kept for callers that used process env. It is a no-op:
// session values live on Global and are applied in childEnviron / sniff paths.
func ExportSocatEnv(g *Global) {}

// RememberTLSPeer fills SOCAT_OPENSSL_X509_* from the peer certificate when present.
func RememberTLSPeer(g *Global, c net.Conn) {
	if g == nil || c == nil {
		return
	}
	tc, ok := c.(*tls.Conn)
	if !ok {
		// tls.NewListener returns *tls.Conn; still handle wrappers.
		if u, ok := c.(interface{ NetConn() net.Conn }); ok {
			if tc2, ok := u.NetConn().(*tls.Conn); ok {
				tc = tc2
			} else {
				return
			}
		} else {
			return
		}
	}
	// Ensure handshake finished (Accept should already have done this).
	if err := tc.Handshake(); err != nil {
		return
	}
	st := tc.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return
	}
	leaf := st.PeerCertificates[0]
	// Classic format: "C = XY, CN = localhost, O = dest-unreach, OU = socat, L = Lunar Base"
	g.TLSPeerSubject = FormatTLSName(leaf.Subject)
	g.TLSPeerIssuer = FormatTLSName(leaf.Issuer)
	g.TLSPeerCommonName = leaf.Subject.CommonName
	g.TLSPeerCountry = firstOrEmpty(leaf.Subject.Country)
	g.TLSPeerLocality = firstOrEmpty(leaf.Subject.Locality)
	g.TLSPeerOrg = firstOrEmpty(leaf.Subject.Organization)
	g.TLSPeerOrgUnit = firstOrEmpty(leaf.Subject.OrganizationalUnit)
}

// FormatTLSName matches classic SOCAT_OPENSSL_X509_SUBJECT / ISSUER layout.
func FormatTLSName(n pkix.Name) string {
	// Order used by classic test.sh expected values: C, CN, O, OU, L
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

// ParseSocatData parses classic dalan-ish SOCKET address data:
//
//	"path\0"  double-quoted string with C-style escapes
//	\"path\0\"  same after shell leaves backslash-quotes (test.sh SOCKET_CONNECT_UNIX)
//	xHHHH...  hex (segments may be separated by extra 'x')
//	'c'       single character only (classic dalan; multi-char → syntax error)
//
// Raw unquoted paths are also accepted for AF_UNIX convenience.
// Returns an error on classic-style syntax errors (DALAN_NO_SIGSEGV expects rc=1).
func ParseSocatData(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	// Shell-escaped double quotes: \"...\" (classic test.sh leaves these in argv).
	if strings.HasPrefix(s, `\"`) {
		s = unescapeShellQuotes(s)
	}
	// Classic dalan: leading ' is a single character, not a quoted string.
	// SOCKET-LISTEN:1:1:'/tmp/sock' is intentionally a syntax error (DALAN_NO_SIGSEGV).
	if s[0] == '\'' {
		if len(s) < 3 || s[len(s)-1] != '\'' {
			return nil, fmt.Errorf("syntax error in %q", s)
		}
		// Exactly one character between quotes (with optional \escape).
		inner := s[1 : len(s)-1]
		if len(inner) == 1 {
			return []byte{inner[0]}, nil
		}
		if len(inner) == 2 && inner[0] == '\\' {
			return []byte{escapeByte(inner[1])}, nil
		}
		return nil, fmt.Errorf("syntax error in %q", s)
	}
	// Double-quoted string (classic UNIX SOCKET address form).
	if s[0] == '"' {
		out, rest, err := parseDalanString(s)
		if err != nil {
			return nil, err
		}
		if rest != "" {
			// trailing garbage after string — still allow concatenated x...
			more, err := ParseSocatData(rest)
			if err != nil {
				return nil, err
			}
			return append(out, more...), nil
		}
		return out, nil
	}
	// Hex form: xHHHH or xHHHHxHHHH...
	if strings.HasPrefix(s, "x") || strings.HasPrefix(s, "X") {
		var out []byte
		for _, part := range strings.Split(s, "x") {
			if part == "" {
				continue
			}
			// also handle X
			part = strings.TrimPrefix(part, "X")
			if part == "" {
				continue
			}
			if len(part)%2 == 1 {
				// classic: odd number of hex digits is a syntax error
				return nil, fmt.Errorf("syntax error in %q", s)
			}
			b, err := hex.DecodeString(part)
			if err != nil {
				return nil, fmt.Errorf("syntax error in %q", s)
			}
			out = append(out, b...)
		}
		return out, nil
	}
	// Unquoted: expand \ escapes (path convenience).
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(escapeByte(s[i]))
			continue
		}
		b.WriteByte(s[i])
	}
	return []byte(b.String()), nil
}

func FormatSocatAddr(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		// Expand to full form when possible for test comparisons.
		return "[" + ExpandIPv6(ip) + "]"
	}
	return host
}

func ExpandIPv6(ip net.IP) string {
	if ip == nil {
		return ""
	}
	ip = ip.To16()
	if ip == nil {
		return ""
	}
	// Classic often prints full zero-padded form for ::1
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
		ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15])
}
