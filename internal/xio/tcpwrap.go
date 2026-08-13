package xio

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// tcpwrapConfig holds classic libwrap / tcpwrappers options for peer checks.
type tcpwrapConfig struct {
	enabled bool
	daemon  string // service name in hosts.* (default: progname / "socat")
	allow   string // path to hosts.allow
	deny    string // path to hosts.deny
}

// parseTCPWrap extracts hosts-allow / hosts-deny / tcpwrap-etc / tcpwrap options.
// Any of these enables the filter (classic dolibwrap).
func parseTCPWrap(s parse.Spec, g *Global) tcpwrapConfig {
	cfg := tcpwrapConfig{}
	// Explicit table paths
	if s.HasOption("hosts-allow") || s.HasOption("allow-table") || s.HasOption("tcpwrap-hosts-allow-table") {
		cfg.enabled = true
		cfg.allow = FirstNonEmpty(
			s.OptionValue("hosts-allow", ""),
			s.OptionValue("allow-table", ""),
			s.OptionValue("tcpwrap-hosts-allow-table", ""),
		)
	}
	if s.HasOption("hosts-deny") || s.HasOption("deny-table") || s.HasOption("tcpwrap-hosts-deny-table") {
		cfg.enabled = true
		cfg.deny = FirstNonEmpty(
			s.OptionValue("hosts-deny", ""),
			s.OptionValue("deny-table", ""),
			s.OptionValue("tcpwrap-hosts-deny-table", ""),
		)
	}
	// Directory containing hosts.allow / hosts.deny
	etc := FirstNonEmpty(
		s.OptionValue("tcpwrap-etc", ""),
		s.OptionValue("tcpwrap-dir", ""),
	)
	if etc != "" {
		cfg.enabled = true
		if cfg.allow == "" {
			cfg.allow = filepath.Join(etc, "hosts.allow")
		}
		if cfg.deny == "" {
			cfg.deny = filepath.Join(etc, "hosts.deny")
		}
	}
	// Bare tcpwrap / libwrap / wrap / tcpwrappers enables with default tables
	// and optional daemon name as the option value.
	for _, name := range []string{"tcpwrap", "tcpwrappers", "tcpwrapper", "libwrap", "wrap"} {
		if s.HasOption(name) {
			cfg.enabled = true
			if v := s.OptionValue(name, ""); v != "" && v != "1" {
				cfg.daemon = v
			}
			break
		}
	}
	if !cfg.enabled {
		return cfg
	}
	if cfg.daemon == "" {
		if g != nil && g.Progname != "" {
			cfg.daemon = g.Progname
		} else {
			cfg.daemon = "socat"
		}
	}
	// Default system tables if none set (classic).
	if cfg.allow == "" {
		cfg.allow = "/etc/hosts.allow"
	}
	if cfg.deny == "" {
		cfg.deny = "/etc/hosts.deny"
	}
	return cfg
}

func FirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// tcpwrapAllowed returns nil if the peer is allowed, or an error to refuse.
// Classic hosts_access: allow table first; then deny; default permit if neither matches.
func tcpwrapAllowed(cfg tcpwrapConfig, peer net.Addr, local net.Addr) error {
	if !cfg.enabled {
		return nil
	}
	_ = local // classic passes server sin for libwrap; we match client only
	clientIP, bareHost := peerIPOnly(peer)
	if clientIP == "" && bareHost == "" {
		return fmt.Errorf("refusing connection from %s due to tcpwrapper option", peer)
	}
	// Match by IP first (no reverse DNS) so reject is fast enough that the
	// client has not written yet — avoids RST vs FIN (TCP4WRAPPERS_* expect 0).
	if matchHostsTable(cfg.allow, cfg.daemon, clientIP, "") {
		return nil
	}
	// Only reverse-lookup when tables may name hosts (TCP4WRAPPERS_NAME).
	clientHost := ""
	if clientIP != "" && tablesMayNeedHostname(cfg.allow, cfg.deny) {
		clientHost = reverseHost(clientIP)
		if clientHost != "" && matchHostsTable(cfg.allow, cfg.daemon, clientIP, clientHost) {
			return nil
		}
	}
	if matchHostsTable(cfg.deny, cfg.daemon, clientIP, clientHost) {
		return fmt.Errorf("refusing connection from %s due to tcpwrapper option", peer)
	}
	// Classic default: permit if not denied
	return nil
}

func peerIPOnly(peer net.Addr) (ipStr, bare string) {
	if peer == nil {
		return "", ""
	}
	host, _, err := net.SplitHostPort(peer.String())
	if err != nil {
		host = peer.String()
	}
	host = StripBrackets(host)
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), ""
	}
	return "", host
}

// reverseHost returns a verified reverse-DNS name for ipStr, or "".
// Classic/libwrap-style: name is only trusted when it forward-resolves back
// to the client IP. Without this, systems that map all 127/8 to "localhost"
// would falsely pass TCP4WRAPPERS_NAME (allow localhost, client SECONDADDR).
func reverseHost(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	names, err := net.LookupAddr(ipStr)
	if err != nil || len(names) == 0 {
		return ""
	}
	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		ips, err := net.LookupIP(name)
		if err != nil {
			continue
		}
		for _, resolved := range ips {
			if resolved.Equal(ip) {
				return name
			}
		}
	}
	return ""
}

// tablesMayNeedHostname is true if allow/deny list any non-IP, non-ALL token.
func tablesMayNeedHostname(paths ...string) bool {
	for _, path := range paths {
		if path == "" {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		need := false
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			_, clientList, ok := splitHostsAccessLine(line)
			if !ok {
				continue
			}
			for _, tok := range splitHostsList(clientList) {
				if strings.EqualFold(tok, "ALL") {
					continue
				}
				if net.ParseIP(StripBrackets(tok)) != nil {
					continue
				}
				need = true
				break
			}
			if need {
				break
			}
		}
		f.Close()
		if need {
			return true
		}
	}
	return false
}

// matchHostsTable returns true if daemon+client match a non-comment line.
// Supports classic subset: daemon_list: client_list [: shell_command]
// daemon ALL / exact name; client ALL / IP / hostname / [ipv6] (case-insensitive).
func matchHostsTable(path, daemon, clientIP, clientHost string) bool {
	if path == "" {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		daemonList, clientList, ok := splitHostsAccessLine(line)
		if !ok {
			continue
		}
		if !listMatchesDaemon(daemonList, daemon) {
			continue
		}
		if listMatchesClient(clientList, clientIP, clientHost) {
			return true
		}
	}
	return false
}

// splitHostsAccessLine splits "daemon_list : client_list [ : shell_command ]".
// Colons inside [...] (IPv6) are not field separators.
func splitHostsAccessLine(line string) (daemonList, clientList string, ok bool) {
	i := indexHostsFieldSep(line, 0)
	if i < 0 {
		return "", "", false
	}
	daemonList = strings.TrimSpace(line[:i])
	rest := strings.TrimSpace(line[i+1:])
	// Optional third field (shell command); stop at next unbracketed colon.
	j := indexHostsFieldSep(rest, 0)
	if j >= 0 {
		clientList = strings.TrimSpace(rest[:j])
	} else {
		clientList = rest
	}
	return daemonList, clientList, true
}

// indexHostsFieldSep finds the next ':' that is not inside [...].
func indexHostsFieldSep(s string, from int) int {
	depth := 0
	for i := from; i < len(s); i++ {
		switch s[i] {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case ':':
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func listMatchesDaemon(list, daemon string) bool {
	for _, tok := range splitHostsList(list) {
		if strings.EqualFold(tok, "ALL") || strings.EqualFold(tok, daemon) {
			return true
		}
	}
	return false
}

func listMatchesClient(list, clientIP, clientHost string) bool {
	for _, tok := range splitHostsList(list) {
		if strings.EqualFold(tok, "ALL") {
			return true
		}
		// Strip brackets for IPv6 tokens like [::1] (TCPWRAPPERS_TCP6ADDR).
		tokIP := StripBrackets(tok)
		// Exact IP string
		if clientIP != "" && (tok == clientIP || tokIP == clientIP) {
			return true
		}
		// Parsed IP equality (normalize v4/v6, brackets)
		if clientIP != "" {
			if a, b := net.ParseIP(tokIP), net.ParseIP(clientIP); a != nil && b != nil && a.Equal(b) {
				return true
			}
		}
		// Hostname (case-insensitive, optional trailing dot)
		if clientHost != "" {
			th := strings.TrimSuffix(strings.ToLower(tok), ".")
			ch := strings.TrimSuffix(strings.ToLower(clientHost), ".")
			if th == ch {
				return true
			}
			// Suffix: .example.com style (leading dot)
			if strings.HasPrefix(tok, ".") && strings.HasSuffix(ch, strings.ToLower(tok)) {
				return true
			}
		}
	}
	return false
}

func splitHostsList(s string) []string {
	// Comma or space separated (classic allows both).
	s = strings.ReplaceAll(s, ",", " ")
	fields := strings.Fields(s)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}
