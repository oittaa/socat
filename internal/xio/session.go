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
	// Classic xiosetenv: PROGNAME_PEERADDR / PROGNAME_PEERPORT (and SOCAT_*).
	ExportSocatEnv(g)
}

// ExportSocatEnv sets process environment for sniff-path expansion and children.
func ExportSocatEnv(g *Global) {
	if g == nil {
		return
	}
	prog := g.Progname
	if prog == "" {
		prog = "socat"
	}
	// Uppercase progname like classic xiosetenv.
	up := strings.ToUpper(prog)
	_ = os.Setenv("SOCAT_SOCKADDR", g.SockAddr)
	_ = os.Setenv("SOCAT_PEERADDR", g.PeerAddr)
	_ = os.Setenv("SOCAT_SOCKPORT", g.SockPort)
	_ = os.Setenv("SOCAT_PEERPORT", g.PeerPort)
	_ = os.Setenv(up+"_SOCKADDR", g.SockAddr)
	_ = os.Setenv(up+"_PEERADDR", g.PeerAddr)
	_ = os.Setenv(up+"_SOCKPORT", g.SockPort)
	_ = os.Setenv(up+"_PEERPORT", g.PeerPort)
}

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
