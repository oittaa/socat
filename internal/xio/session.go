package xio

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	socat "github.com/oittaa/socat"
)

// RememberAddrs fills SOCAT_* environment fields on g from a live connection.
// Also exports process env used by -r/-R path expansion ($SERVER0_PEERADDR).
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
		mu := (*sync.Mutex)(atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&g.sessionMu))))
		if mu != nil {
			return mu
		}
		created := new(sync.Mutex)
		// #nosec G103 -- CAS publishes a heap mutex; Global stays copyable.
		if atomic.CompareAndSwapPointer(
			(*unsafe.Pointer)(unsafe.Pointer(&g.sessionMu)),
			nil,
			unsafe.Pointer(created),
		) {
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
	return cloneStringMap(g.SessionVars)
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
	return g.SessionVars[name]
}

// SetSessionEnv records a per-session output variable without its executable
// prefix. It is exported for address implementations such as POSIXMQ.
func SetSessionEnv(g *Global, name, value string) {
	if g == nil || name == "" {
		return
	}
	unlock := g.lockSession()
	defer unlock()
	if g.SessionVars == nil {
		g.SessionVars = make(map[string]string)
	}
	g.SessionVars[name] = value
}

// sessionEnv returns SOCAT_* / PROGNAME_* values from this session.
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
	unlock := g.lockSession()
	for name, value := range g.SessionVars {
		values[name] = value
	}
	unlock()

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
	// Full zero-padded form for ::1.
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
		ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15])
}
