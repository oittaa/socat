package xio

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	socat "github.com/oittaa/socat"
)

// rememberAddrs writes this session's SOCAT_* address fields from a live
// connection. Also used by -r/-R path expansion ($SERVER0_PEERADDR).
func rememberAddrs(g *Global, c net.Conn) {
	if g == nil || c == nil {
		return
	}
	if la := c.LocalAddr(); la != nil {
		host, port, err := net.SplitHostPort(la.String())
		if err == nil {
			g.Peer.SockAddr = FormatSocatAddr(host)
			g.Peer.SockPort = port
		} else {
			g.Peer.SockAddr = la.String()
		}
	}
	if ra := c.RemoteAddr(); ra != nil {
		host, port, err := net.SplitHostPort(ra.String())
		if err == nil {
			g.Peer.PeerAddr = FormatSocatAddr(host)
			g.Peer.PeerPort = port
		} else {
			g.Peer.PeerAddr = ra.String()
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

// lockSession locks this Global's SessionVars mutex. Constructors store one;
// a zero-value session still creates it on first use.
func (g *Global) lockSession() func() {
	if g == nil {
		return func() {}
	}
	mu := g.loadOrStoreSessionMu()
	mu.Lock()
	return mu.Unlock
}

func (g *Global) loadOrStoreSessionMu() *sync.Mutex {
	for {
		if mu := g.sessionMu.Load(); mu != nil {
			return mu
		}
		created := new(sync.Mutex)
		if g.sessionMu.CompareAndSwap(nil, created) {
			return created
		}
	}
}

func (g *Global) cloneSessionVars() map[string]string {
	if g == nil {
		return nil
	}
	unlock := g.lockSession()
	defer unlock()
	return cloneStringMap(g.Peer.SessionVars)
}

// SessionVarsSnapshot copies SessionVars for EXEC/SYSTEM child environments.
func (g *Global) SessionVarsSnapshot() map[string]string {
	return g.cloneSessionVars()
}

// SessionVar returns one SessionVars entry. Tests use this instead of reading
// the map during concurrent recverr drains.
func (g *Global) SessionVar(name string) string {
	if g == nil {
		return ""
	}
	unlock := g.lockSession()
	defer unlock()
	return g.Peer.SessionVars[name]
}

// SetSessionVar records a per-session output variable. Nil receivers do nothing.
func (g *Global) SetSessionVar(name, value string) { SetSessionEnv(g, name, value) }

// Infof logs at info. Nil receivers and a nil logger do nothing.
func (g *Global) Infof(format string, args ...any) {
	if g != nil {
		g.Log.Infof(format, args...)
	}
}

// Noticef logs at notice. Nil receivers and a nil logger do nothing.
func (g *Global) Noticef(format string, args ...any) {
	if g != nil {
		g.Log.Noticef(format, args...)
	}
}

// SetSessionEnv records a per-session output variable without its executable
// prefix. It is exported for address implementations such as POSIXMQ.
func SetSessionEnv(g *Global, name, value string) {
	if g == nil || name == "" {
		return
	}
	unlock := g.lockSession()
	defer unlock()
	if g.Peer.SessionVars == nil {
		g.Peer.SessionVars = make(map[string]string)
	}
	g.Peer.SessionVars[name] = value
}

// sessionFields is one locked copy of the peer fields published as SOCAT_*.
type sessionFields struct {
	sockAddr string
	peerAddr string
	sockPort string
	peerPort string
	vars     map[string]string
	tls      map[string]string
	hasTLS   bool
}

// snapshotSessionFields copies address, TLS, and session variables under the
// session lock so one read does not mix those fields.
func (g *Global) snapshotSessionFields() sessionFields {
	if g == nil {
		return sessionFields{}
	}
	unlock := g.lockSession()
	defer unlock()
	return sessionFields{
		sockAddr: g.Peer.SockAddr,
		peerAddr: g.Peer.PeerAddr,
		sockPort: g.Peer.SockPort,
		peerPort: g.Peer.PeerPort,
		vars:     cloneStringMap(g.Peer.SessionVars),
		tls:      cloneStringMap(g.Peer.TLSVars),
		hasTLS:   g.Peer.TLSVars != nil,
	}
}

// sessionEnvPrefixes is SOCAT, plus the uppercased progname when that name
// is not socat. An empty progname uses socat.
func sessionEnvPrefixes(prog string) []string {
	if prog == "" {
		prog = "socat"
	}
	prefixes := []string{"SOCAT"}
	if up := strings.ToUpper(prog); up != "SOCAT" {
		prefixes = append(prefixes, up)
	}
	return prefixes
}

func formatSessionEnv(prefixes []string, fields sessionFields) []string {
	if len(prefixes) == 0 {
		return nil
	}
	values := map[string]string{
		"VERSION":  socat.Version,
		"PID":      strconv.Itoa(os.Getpid()),
		"PPID":     strconv.Itoa(os.Getpid()),
		"SOCKADDR": fields.sockAddr,
		"PEERADDR": fields.peerAddr,
		"SOCKPORT": fields.sockPort,
		"PEERPORT": fields.peerPort,
	}
	for name, value := range fields.vars {
		values[name] = value
	}
	names := sortedKeys(values)
	tlsNames := sortedKeys(fields.tls)
	out := make([]string, 0, len(prefixes)*(len(names)+2*len(tlsNames)))
	for _, prefix := range prefixes {
		for _, name := range names {
			out = append(out, prefix+"_"+name+"="+values[name])
		}
		for _, name := range tlsNames {
			value := fields.tls[name]
			out = append(out,
				prefix+"_TLS_"+name+"="+value,
				prefix+"_OPENSSL_"+name+"="+value,
			)
		}
	}
	return out
}

// sessionEnv returns SOCAT_* / PROGNAME_* values from this session.
func sessionEnv(g *Global) []string {
	if g == nil {
		return nil
	}
	return formatSessionEnv(sessionEnvPrefixes(g.Options().Progname), g.snapshotSessionFields())
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
func ChildEnviron(g *Global) []string {
	var prefixes []string
	var fields sessionFields
	if g != nil {
		prefixes = sessionEnvPrefixes(g.Options().Progname)
		fields = g.snapshotSessionFields()
	}
	extra := formatSessionEnv(prefixes, fields)
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
	if fields.hasTLS {
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
	case "SOCKADDR", "PEERADDR", "SOCKPORT", "PEERPORT":
		fields := g.snapshotSessionFields()
		switch name {
		case "SOCKADDR":
			return fields.sockAddr, true
		case "PEERADDR":
			return fields.peerAddr, true
		case "SOCKPORT":
			return fields.sockPort, true
		default:
			return fields.peerPort, true
		}
	}
	for _, entry := range sessionEnv(g) {
		if i := strings.IndexByte(entry, '='); i > 0 && entry[:i] == name {
			return entry[i+1:], true
		}
	}
	return "", false
}

func FormatSocatAddr(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		// Expand to full form when possible for test comparisons.
		return "[" + expandIPv6(ip) + "]"
	}
	return host
}

func expandIPv6(ip net.IP) string {
	if ip == nil {
		return ""
	}
	ip = ip.To16()
	if ip == nil {
		return ""
	}
	// Full zero-padded form for ::1.
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
		ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15])
}
