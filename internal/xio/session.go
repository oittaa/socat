package xio

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	socat "github.com/oittaa/socat"
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
	if carrier, ok := c.(interface{ SessionEnvironment() map[string]string }); ok {
		for name, value := range carrier.SessionEnvironment() {
			SetSessionEnv(g, name, value)
		}
	}
	// Session fields stay on g. EXEC children get them via childEnviron.
	// Do not os.Setenv: fork goroutines would race on process environment.
}

// SetSessionEnv records a per-session output variable without its executable
// prefix. It is exported for address implementations such as POSIXMQ.
func SetSessionEnv(g *Global, name, value string) {
	if g == nil || name == "" {
		return
	}
	if g.SessionVars == nil {
		g.SessionVars = make(map[string]string)
	}
	g.SessionVars[name] = value
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
	prefixes := []string{"SOCAT"}
	if up != "SOCAT" {
		prefixes = append(prefixes, up)
	}
	values := map[string]string{
		"VERSION":  socat.Version,
		"PID":      strconv.Itoa(os.Getpid()),
		"PPID":     strconv.Itoa(os.Getpid()),
		"SOCKADDR": g.SockAddr,
		"PEERADDR": g.PeerAddr,
		"SOCKPORT": g.SockPort,
		"PEERPORT": g.PeerPort,
	}
	for name, value := range g.SessionVars {
		values[name] = value
	}

	names := sortedKeys(values)
	tlsNames := sortedKeys(g.TLSVars)
	out := make([]string, 0, len(prefixes)*(len(names)+2*len(tlsNames)))
	for _, prefix := range prefixes {
		for _, name := range names {
			out = append(out, prefix+"_"+name+"="+values[name])
		}
		for _, name := range tlsNames {
			value := g.TLSVars[name]
			out = append(out,
				prefix+"_TLS_"+name+"="+value,
				prefix+"_OPENSSL_"+name+"="+value,
			)
		}
	}
	return out
}

func sortedKeys(values map[string]string) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
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
	var dropPrefixes []string
	if g != nil && g.TLSVars != nil {
		prog := g.Progname
		if prog == "" {
			prog = "socat"
		}
		prefixes := []string{"SOCAT"}
		if up := strings.ToUpper(prog); up != "SOCAT" {
			prefixes = append(prefixes, up)
		}
		for _, prefix := range prefixes {
			dropPrefixes = append(dropPrefixes, prefix+"_TLS_", prefix+"_OPENSSL_")
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
		skip := false
		for _, prefix := range dropPrefixes {
			if strings.HasPrefix(k, prefix) {
				skip = true
				break
			}
		}
		if skip {
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
	switch name {
	case "SOCKADDR":
		return g.SockAddr, true
	case "PEERADDR":
		return g.PeerAddr, true
	case "SOCKPORT":
		return g.SockPort, true
	case "PEERPORT":
		return g.PeerPort, true
	}
	for _, entry := range sessionEnv(g) {
		if i := strings.IndexByte(entry, '='); i > 0 && entry[:i] == name {
			return entry[i+1:], true
		}
	}
	return "", false
}

// RememberTLSPeer records negotiated TLS and peer-certificate metadata. The
// child environment exposes preferred SOCAT_TLS_* names and SOCAT_OPENSSL_*
// compatibility aliases.
func RememberTLSPeer(g *Global, c net.Conn, timeout time.Duration) error {
	if c == nil {
		return nil
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
	// Classic format: "C = XY, CN = localhost, O = dest-unreach, OU = socat, L = Lunar Base"
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
