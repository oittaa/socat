package xio

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/logx"
)

// tcpwrapLookupTimeout bounds one peer's reverse lookup so a silent
// nameserver cannot stall the accept loop.
const tcpwrapLookupTimeout = 2 * time.Second

// hostsAccessLineMax is the longest physical hosts_access line. A longer
// line, a missing final newline, or a broken continuation is a framing error.
const hostsAccessLineMax = 2047

// tcpwrapConfig holds libwrap / tcpwrappers options for peer checks.
type tcpwrapConfig struct {
	enabled        bool
	daemon         string // service name in hosts.* (default: progname / "socat")
	daemonExplicit bool   // user supplied tcpwrap=<name>, including an empty name
	allow          string // path to hosts.allow
	deny           string // path to hosts.deny
	allowRequired  bool   // explicitly selected tables must be readable
	denyRequired   bool
}

// parseTCPWrap extracts hosts-allow / hosts-deny / tcpwrap-etc / tcpwrap options.
// Any of these enables the filter.
func parseTCPWrap(policy addrconfig.Network, opts Options) tcpwrapConfig {
	cfg := tcpwrapConfig{}
	if policy.HostsAllow.Set {
		cfg.enabled = true
		cfg.allowRequired = true
		cfg.allow = policy.HostsAllow.Value
	}
	if policy.HostsDeny.Set {
		cfg.enabled = true
		cfg.denyRequired = true
		cfg.deny = policy.HostsDeny.Value
	}
	if policy.TCPWrapEtc.Set && policy.TCPWrapEtc.Value != "" {
		cfg.enabled = true
		if cfg.allow == "" {
			cfg.allow = filepath.Join(policy.TCPWrapEtc.Value, "hosts.allow")
			cfg.allowRequired = true
		}
		if cfg.deny == "" {
			cfg.deny = filepath.Join(policy.TCPWrapEtc.Value, "hosts.deny")
			cfg.denyRequired = true
		}
	}
	if policy.TCPWrap.Set {
		cfg.enabled = true
		if policy.TCPWrapDaemon.Set && !policy.TCPWrapDaemon.Omitted {
			cfg.daemon = policy.TCPWrapDaemon.Value
			cfg.daemonExplicit = true
		}
	}
	if !cfg.enabled {
		return cfg
	}
	if cfg.daemon == "" && !cfg.daemonExplicit {
		if opts.Progname != "" {
			cfg.daemon = opts.Progname
		} else {
			cfg.daemon = "socat"
		}
	}
	// Default system tables if none set.
	if cfg.allow == "" {
		cfg.allow = "/etc/hosts.allow"
	}
	if cfg.deny == "" {
		cfg.deny = "/etc/hosts.deny"
	}
	return cfg
}

// hostsAccessSyntaxError is a hosts.allow / hosts.deny pattern this build
// does not evaluate. Callers deny the peer.
type hostsAccessSyntaxError struct {
	Detail string
}

func (e *hostsAccessSyntaxError) Error() string {
	return e.Detail
}

// hostsSyntax refuses a pattern this build does not evaluate.
// Skipping the token would permit the peer.
func hostsSyntax(tok string) error {
	return &hostsAccessSyntaxError{Detail: fmt.Sprintf("unsupported hosts_access syntax %q", tok)}
}

// LogRefusedPeer logs a peer-filter refusal. Unsupported hosts_access
// syntax is a warning; other refusals stay at notice.
func LogRefusedPeer(log *logx.Logger, err error) {
	if log == nil || err == nil {
		return
	}
	var syntax *hostsAccessSyntaxError
	if errors.As(err, &syntax) {
		log.Warningf("%s", err)
		return
	}
	log.Noticef("%s", err)
}

func tcpwrapAllowedWithResolver(ctx context.Context, resolver *net.Resolver, cfg tcpwrapConfig, peer net.Addr, local net.Addr, log *logx.Logger) error {
	if !cfg.enabled {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	client := newEndpoint(peer, ctx, resolver)
	if client.ip == nil && client.literal == "" {
		return refusePeer(peer)
	}
	server := newEndpoint(local, ctx, resolver)
	allow, err := readHostsTable(cfg.allow, cfg.allowRequired)
	if err != nil {
		return err
	}
	deny, err := readHostsTable(cfg.deny, cfg.denyRequired)
	if err != nil {
		return err
	}
	// A broken allow file drops the bad line and everything after it.
	warnFrame(log, allow.frame)
	verdict, err := matchHostsTable(allow.lines, cfg.daemon, client, server, true, log)
	if err != nil {
		return refuseOrPass(peer, err)
	}
	switch verdict {
	case verdictPermit:
		return nil
	case verdictDeny:
		return refusePeer(peer)
	}
	verdict, err = matchHostsTable(deny.lines, cfg.daemon, client, server, false, log)
	if err != nil {
		return refuseOrPass(peer, err)
	}
	switch verdict {
	case verdictPermit:
		if deny.frame != nil {
			warnFrame(log, deny.frame)
		}
		return nil
	case verdictDeny:
		if deny.frame != nil {
			warnFrame(log, deny.frame)
		}
		return refusePeer(peer)
	}
	// A broken deny file denies every peer that did not match an earlier line.
	if deny.frame != nil {
		return refuseOrPass(peer, deny.frame)
	}
	return nil
}

func warnFrame(log *logx.Logger, frame error) {
	if log == nil || frame == nil {
		return
	}
	log.Warningf("%s", frame)
}

func refusePeer(peer net.Addr) error {
	return fmt.Errorf("refusing connection from %s due to tcpwrapper option", peer)
}

func refuseOrPass(peer net.Addr, err error) error {
	return fmt.Errorf("refusing connection from %s due to tcpwrapper option: %w", peer, err)
}

type nameStatus int

const (
	nameUnknown nameStatus = iota
	nameKnown
	nameParanoid
)

type accessVerdict int

const (
	verdictNone accessVerdict = iota
	verdictPermit
	verdictDeny
)

// endpoint is one side of a hosts_access comparison. Hostname lookup is
// deferred until a pattern needs it.
type endpoint struct {
	ip       net.IP
	zone     string
	addrText string
	literal  string
	port     int
	ctx      context.Context
	resolver *net.Resolver

	looked bool
	name   string
	status nameStatus
	err    error
}

func newEndpoint(addr net.Addr, ctx context.Context, resolver *net.Resolver) *endpoint {
	ip, zone, literal, port := addrIdentity(addr)
	text := "unknown"
	if ip != nil {
		text = ip.String()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return &endpoint{
		ip:       ip,
		zone:     zone,
		addrText: text,
		literal:  literal,
		port:     port,
		ctx:      ctx,
		resolver: resolver,
	}
}

func addrIdentity(addr net.Addr) (net.IP, string, string, int) {
	if addr == nil {
		return nil, "", "", 0
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		if a == nil {
			return nil, "", "", 0
		}
		return a.IP, a.Zone, "", a.Port
	case *net.UDPAddr:
		if a == nil {
			return nil, "", "", 0
		}
		return a.IP, a.Zone, "", a.Port
	case *net.IPAddr:
		if a == nil {
			return nil, "", "", 0
		}
		return a.IP, a.Zone, "", 0
	}
	host, portText, err := net.SplitHostPort(addr.String())
	port := 0
	if err != nil {
		host = addr.String()
	} else if p, conv := strconv.Atoi(portText); conv == nil {
		port = p
	}
	host = StripBrackets(host)
	if i := strings.LastIndex(host, "%"); i >= 0 {
		if ip := net.ParseIP(host[:i]); ip != nil {
			return ip, host[i+1:], "", port
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip, "", "", port
	}
	return nil, "", host, port
}

func lookupHostStatus(ctx context.Context, resolver *net.Resolver, ipStr string) (string, nameStatus, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", nameUnknown, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	// The first PTR only. A deadline here denies this peer and leaves the
	// session context running.
	parent := ctx
	lookupCtx, cancel := context.WithTimeout(parent, tcpwrapLookupTimeout)
	defer cancel()
	names, err := resolver.LookupAddr(lookupCtx, ipStr)
	if parent.Err() != nil {
		return "", nameUnknown, parent.Err()
	}
	if lookupCtx.Err() != nil {
		return "", nameUnknown, hostsSyntax("reverse lookup timed out")
	}
	if err != nil || len(names) == 0 {
		return "", nameUnknown, nil
	}
	name := strings.TrimSuffix(names[0], ".")
	if name == "" {
		return "", nameUnknown, nil
	}
	ips, err := resolver.LookupIP(lookupCtx, "ip", name)
	if parent.Err() != nil {
		return "", nameUnknown, parent.Err()
	}
	if lookupCtx.Err() != nil {
		return "", nameUnknown, hostsSyntax("reverse lookup timed out")
	}
	if err != nil {
		return "", nameParanoid, nil
	}
	for _, resolved := range ips {
		if resolved.Equal(ip) {
			return name, nameKnown, nil
		}
	}
	return "", nameParanoid, nil
}

func (e *endpoint) dnsName() (string, nameStatus, error) {
	if e.looked {
		return e.name, e.status, e.err
	}
	e.looked = true
	if e.ip == nil {
		e.status = nameUnknown
		return "", e.status, nil
	}
	name, status, err := lookupHostStatus(e.ctx, e.resolver, e.ip.String())
	if err != nil {
		e.err = err
		return "", nameUnknown, err
	}
	e.name, e.status = name, status
	return e.name, e.status, nil
}

type hostsTable struct {
	lines []string
	frame error
}

func readHostsTable(path string, required bool) (hostsTable, error) {
	if path == "" {
		return hostsTable{}, nil
	}
	f, err := os.Open(path) // #nosec G304 -- path is an explicit tcpwrap table or a system default
	if err != nil {
		if !required && os.IsNotExist(err) {
			return hostsTable{}, nil
		}
		return hostsTable{}, fmt.Errorf("read tcpwrapper table %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	table, err := parseHostsTable(f)
	if err != nil {
		return hostsTable{}, fmt.Errorf("read tcpwrapper table %q: %w", path, err)
	}
	return table, nil
}

func parseHostsTable(r io.Reader) (hostsTable, error) {
	br := bufio.NewReader(r)
	var table hostsTable
	var pending string
	continued := false
	for {
		phys, hasNL, err := readHostsPhysical(br)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			var syntax *hostsAccessSyntaxError
			if errors.As(err, &syntax) {
				table.frame = err
				return table, nil
			}
			return hostsTable{}, err
		}
		if !hasNL {
			table.frame = hostsSyntax("missing newline")
			return table, nil
		}
		if strings.HasSuffix(phys, "\\\r") {
			table.frame = hostsSyntax("backslash-CRLF continuation")
			return table, nil
		}
		phys = strings.TrimSuffix(phys, "\r")
		if strings.HasSuffix(phys, `\`) {
			pending += phys[:len(phys)-1]
			continued = true
			continue
		}
		if continued {
			table.lines = append(table.lines, pending+phys)
			pending = ""
			continued = false
			continue
		}
		table.lines = append(table.lines, phys)
	}
	if continued {
		table.frame = hostsSyntax("continuation at end of file")
		return table, nil
	}
	return table, nil
}

func readHostsPhysical(br *bufio.Reader) (string, bool, error) {
	var buf []byte
	for {
		b, err := br.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(buf) == 0 {
					return "", false, io.EOF
				}
				return string(buf), false, nil
			}
			return "", false, err
		}
		if b == '\n' {
			return string(buf), true, nil
		}
		if len(buf) >= hostsAccessLineMax {
			return "", false, hostsSyntax("line too long")
		}
		buf = append(buf, b)
	}
}

func matchHostsTable(lines []string, daemon string, client, server *endpoint, fromAllow bool, log *logx.Logger) (accessVerdict, error) {
	for _, raw := range lines {
		if raw == "" || raw[0] == '#' {
			continue
		}
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := splitHostsFields(line)
		if len(fields) < 2 {
			return verdictNone, &hostsAccessSyntaxError{Detail: fmt.Sprintf("unsupported hosts_access syntax: missing \":\" in %q", line)}
		}
		daemonOK, err := matchList(splitHostsList(fields[0]), func(tok string) (bool, error) {
			return serverToken(tok, daemon, server)
		})
		if err != nil {
			return verdictNone, err
		}
		if !daemonOK {
			continue
		}
		clientOK, err := matchList(splitHostsList(fields[1]), func(tok string) (bool, error) {
			return clientToken(tok, client)
		})
		if err != nil {
			return verdictNone, err
		}
		if !clientOK {
			continue
		}
		return applyOptions(fields[2:], fromAllow, log)
	}
	return verdictNone, nil
}

// applyOptions evaluates a hosts_options field. allow and deny must be last.
// twist, aclexec, and unknown options are not executed and deny the peer.
// Side-effect options are not executed; the rule's decision still applies.
func applyOptions(options []string, fromAllow bool, log *logx.Logger) (accessVerdict, error) {
	implicit := verdictDeny
	if fromAllow {
		implicit = verdictPermit
	}
	if len(options) == 1 && options[0] == "" {
		return implicit, nil
	}
	for i, opt := range options {
		parts := strings.Fields(opt)
		if len(parts) == 0 {
			return verdictNone, hostsSyntax(opt)
		}
		key := strings.ToLower(parts[0])
		switch key {
		case "allow", "deny":
			if len(parts) != 1 || i != len(options)-1 {
				return verdictNone, hostsSyntax(opt)
			}
			if key == "allow" {
				return verdictPermit, nil
			}
			return verdictDeny, nil
		case "twist", "aclexec":
			return verdictNone, hostsSyntax(opt)
		case "spawn", "severity", "banners", "nice", "keepalive", "linger", "rfc931", "setenv", "umask", "user":
			if log != nil {
				log.Warningf("tcpwrap option %q is not executed", key)
			}
		default:
			return verdictNone, hostsSyntax(opt)
		}
	}
	return implicit, nil
}

// matchList applies hosts_access EXCEPT. a EXCEPT b EXCEPT c is a EXCEPT (b EXCEPT c).
func matchList(tokens []string, match func(string) (bool, error)) (bool, error) {
	i := 0
	return matchListAt(tokens, &i, match)
}

func matchListAt(tokens []string, i *int, match func(string) (bool, error)) (bool, error) {
	for *i < len(tokens) {
		tok := tokens[*i]
		*i++
		if strings.EqualFold(tok, "EXCEPT") {
			return false, nil
		}
		ok, err := match(tok)
		if err != nil {
			return false, err
		}
		if !ok {
			continue
		}
		for *i < len(tokens) && !strings.EqualFold(tokens[*i], "EXCEPT") {
			*i++
		}
		if *i >= len(tokens) {
			return true, nil
		}
		*i++
		excluded, err := matchListAt(tokens, i, match)
		if err != nil {
			return false, err
		}
		return !excluded, nil
	}
	return false, nil
}

// splitHostsFields splits on unescaped ':' outside [...]. A backslash
// escapes the next byte, so "\:" is a literal colon.
func splitHostsFields(line string) []string {
	var fields []string
	var b strings.Builder
	depth := 0
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\\' && i+1 < len(line) {
			b.WriteByte(line[i+1])
			i++
			continue
		}
		switch c {
		case '[':
			depth++
			b.WriteByte(c)
		case ']':
			if depth > 0 {
				depth--
			}
			b.WriteByte(c)
		case ':':
			if depth == 0 {
				fields = append(fields, strings.TrimSpace(b.String()))
				b.Reset()
				continue
			}
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	fields = append(fields, strings.TrimSpace(b.String()))
	return fields
}

func splitMarker(tok string) (left, right string, ok bool) {
	if len(tok) < 2 {
		return "", "", false
	}
	rel := strings.IndexByte(tok[1:], '@')
	if rel < 0 {
		return "", "", false
	}
	at := rel + 1
	return tok[:at], tok[at+1:], true
}

func serverToken(tok, daemon string, server *endpoint) (bool, error) {
	name, host, ok := splitMarker(tok)
	if !ok {
		if port, isPort := numericPort(tok); isPort {
			return server.port == port, nil
		}
		return stringMatch(tok, daemon)
	}
	matched := false
	if port, isPort := numericPort(name); isPort {
		matched = server.port == port
	} else {
		var err error
		matched, err = stringMatch(name, daemon)
		if err != nil || !matched {
			return false, err
		}
	}
	if !matched {
		return false, nil
	}
	return hostMatch(host, server)
}

// numericPort reports an all-digit daemon token in 0..65535. That token
// matches the local server port.
func numericPort(tok string) (int, bool) {
	if tok == "" {
		return 0, false
	}
	n := 0
	for _, c := range tok {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
		if n > 65535 {
			return 0, false
		}
	}
	return n, true
}

func clientToken(tok string, client *endpoint) (bool, error) {
	_, host, ok := splitMarker(tok)
	if !ok {
		return hostMatch(tok, client)
	}
	matched, err := hostMatch(host, client)
	if err != nil || !matched {
		return false, err
	}
	// user@host needs an IDENT lookup, which is not implemented.
	return false, hostsSyntax(tok)
}

func hostMatch(tok string, ep *endpoint) (bool, error) {
	if tok == "" {
		return false, nil
	}
	switch tok[0] {
	case '@':
		return false, hostsSyntax(tok)
	case '/':
		return false, hostsSyntax(tok)
	case '{':
		return false, hostsSyntax(tok)
	}
	switch strings.ToLower(tok) {
	case "known":
		return knownMatch(ep)
	case "local":
		return localMatch(ep)
	case "unknown":
		return unknownMatch(ep)
	case "paranoid":
		return paranoidMatch(ep)
	}
	if badWildcard(tok) {
		return false, hostsSyntax(tok)
	}
	if strings.Contains(tok, "/") {
		return matchNet(tok, ep)
	}
	if addr, ok := parseHostIP(tok); ok {
		return ipMatches(addr, ep), nil
	}
	return hostStringMatch(tok, ep)
}

func knownMatch(ep *endpoint) (bool, error) {
	if ep.ip == nil {
		return false, nil
	}
	_, status, err := ep.dnsName()
	if err != nil {
		return false, err
	}
	return status == nameKnown, nil
}

func localMatch(ep *endpoint) (bool, error) {
	name, status, err := ep.dnsName()
	if err != nil {
		return false, err
	}
	return status == nameKnown && !strings.Contains(name, "."), nil
}

func unknownMatch(ep *endpoint) (bool, error) {
	if ep.ip == nil {
		return true, nil
	}
	_, status, err := ep.dnsName()
	if err != nil {
		return false, err
	}
	return status == nameUnknown, nil
}

func paranoidMatch(ep *endpoint) (bool, error) {
	if ep.ip == nil {
		return false, nil
	}
	_, status, err := ep.dnsName()
	if err != nil {
		return false, err
	}
	return status == nameParanoid, nil
}

func hostStringMatch(tok string, ep *endpoint) (bool, error) {
	ok, err := stringMatch(tok, ep.addrText)
	if err != nil || ok {
		return ok, err
	}
	if addressShaped(tok) {
		return false, nil
	}
	if ep.literal != "" {
		return stringMatch(tok, ep.literal)
	}
	name, status, err := ep.dnsName()
	if err != nil {
		return false, err
	}
	if status != nameKnown {
		return false, nil
	}
	return stringMatch(tok, name)
}

func addressShaped(tok string) bool {
	if tok == "" {
		return false
	}
	for _, c := range tok {
		if (c < '0' || c > '9') && c != '.' && c != '/' {
			return false
		}
	}
	return true
}

func badWildcard(tok string) bool {
	if !strings.ContainsAny(tok, "*?") {
		return false
	}
	return strings.HasPrefix(tok, ".") || strings.HasSuffix(tok, ".") || strings.Contains(tok, "/")
}

func stringMatch(tok, value string) (bool, error) {
	if tok == "" {
		return false, nil
	}
	if badWildcard(tok) {
		return false, hostsSyntax(tok)
	}
	tok = strings.ToLower(tok)
	value = strings.ToLower(value)
	if strings.HasPrefix(tok, ".") {
		n := len(value) - len(tok)
		return n > 0 && value[n:] == tok, nil
	}
	if tok == "all" {
		return true, nil
	}
	if tok == "known" {
		return value != "unknown", nil
	}
	if strings.HasSuffix(tok, ".") {
		return strings.HasPrefix(value, tok), nil
	}
	if strings.ContainsAny(tok, "*?") {
		return globMatch(tok, value), nil
	}
	return tok == value, nil
}

func globMatch(pat, s string) bool {
	for {
		if pat == "" {
			return s == ""
		}
		if pat[0] == '*' {
			pat = pat[1:]
			if pat == "" {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if globMatch(pat, s[i:]) {
					return true
				}
			}
			return false
		}
		if s == "" || (pat[0] != '?' && pat[0] != s[0]) {
			return false
		}
		pat = pat[1:]
		s = s[1:]
	}
}

func matchNet(tok string, ep *endpoint) (bool, error) {
	netTok, maskTok, ok := strings.Cut(tok, "/")
	if !ok || maskTok == "" || strings.Contains(maskTok, "/") {
		return false, hostsSyntax(tok)
	}
	if strings.Contains(netTok, ":") || strings.HasPrefix(netTok, "[") {
		return matchV6(netTok, maskTok, ep)
	}
	return matchV4(netTok, maskTok, ep)
}

func matchV4(netTok, maskTok string, ep *endpoint) (bool, error) {
	network, ok := parseDottedQuad(netTok)
	if !ok {
		return false, hostsSyntax(netTok + "/" + maskTok)
	}
	var mask [4]byte
	if parsed, ok := parseDottedQuad(maskTok); ok {
		mask = parsed
	} else if bits, ok := parsePrefixLen(maskTok, 32); ok {
		mask = maskFromLen(bits)
	} else {
		return false, hostsSyntax(netTok + "/" + maskTok)
	}
	if mask == [4]byte{} || mask == [4]byte{255, 255, 255, 255} {
		return false, hostsSyntax(netTok + "/" + maskTok)
	}
	if ep.ip == nil {
		return false, nil
	}
	ip4 := ep.ip.To4()
	if ip4 == nil {
		return false, nil
	}
	var got [4]byte
	for i := 0; i < 4; i++ {
		got[i] = ip4[i] & mask[i]
	}
	return got == network, nil
}

func matchV6(netTok, maskTok string, ep *endpoint) (bool, error) {
	whole := netTok + "/" + maskTok
	bits, ok := parsePrefixLen(maskTok, 128)
	if !ok || !strings.HasPrefix(netTok, "[") || !strings.HasSuffix(netTok, "]") {
		return false, hostsSyntax(whole)
	}
	pat, err := netip.ParseAddr(netTok[1 : len(netTok)-1])
	if err != nil || !pat.Is6() {
		return false, hostsSyntax(whole)
	}
	if ep.ip == nil {
		return false, nil
	}
	got, ok := netip.AddrFromSlice(ep.ip)
	if !ok {
		return false, nil
	}
	got = got.Unmap()
	pat = pat.Unmap()
	if !got.Is6() || !pat.Is6() {
		return false, nil
	}
	if pat.Zone() != "" && pat.Zone() != ep.zone {
		return false, nil
	}
	pfx, err := pat.WithZone("").Prefix(bits)
	if err != nil {
		return false, hostsSyntax(whole)
	}
	return pfx.Contains(got.WithZone("")), nil
}

func parseHostIP(tok string) (netip.Addr, bool) {
	s := tok
	if len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']' {
		s = s[1 : len(s)-1]
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

func ipMatches(pat netip.Addr, ep *endpoint) bool {
	if ep.ip == nil {
		return false
	}
	got, ok := netip.AddrFromSlice(ep.ip)
	if !ok {
		return false
	}
	got = got.Unmap()
	if !got.IsValid() || got.BitLen() != pat.BitLen() {
		return false
	}
	if pat.Zone() != "" && pat.Zone() != ep.zone {
		return false
	}
	return got.WithZone("") == pat.WithZone("")
}

func parseDottedQuad(s string) ([4]byte, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return [4]byte{}, false
	}
	var out [4]byte
	for i, p := range parts {
		if p == "" || len(p) > 3 {
			return [4]byte{}, false
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return [4]byte{}, false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return [4]byte{}, false
		}
		out[i] = byte(n)
	}
	return out, true
}

func parsePrefixLen(s string, max int) (int, bool) {
	if s == "" || len(s) > 3 {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	if n > max {
		return 0, false
	}
	return n, true
}

func maskFromLen(bits int) [4]byte {
	var mask [4]byte
	for i := 0; i < 4; i++ {
		if bits >= 8 {
			mask[i] = 0xff
			bits -= 8
			continue
		}
		if bits > 0 {
			mask[i] = byte(0xff << (8 - bits))
		}
		break
	}
	return mask
}

func splitHostsList(s string) []string {
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
