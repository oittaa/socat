package xio

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

const defaultDNSPort = 53

// ParseResNSAddr validates res-nsaddr and returns a dialable host:port.
// Classic TYPE_IP4SOCK (xioopts.c at tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is unchanged) accepts an IPv4
// address or hostname plus an optional port, stored in sockaddr_in
// _res.nsaddr_list[0]. IPv6 nameserver literals are rejected to match that
// public interface.
func ParseResNSAddr(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("res-nsaddr: nameserver address is empty")
	}

	host, port, err := splitResNSAddr(value)
	if err != nil {
		return "", err
	}
	if err := validateResNSHost(host); err != nil {
		return "", err
	}

	portNum := defaultDNSPort
	if port != "" {
		portNum, err = strconv.Atoi(port)
		if err != nil {
			portNum, err = net.LookupPort("udp", port)
		}
		if err != nil || portNum < 0 || portNum > 65535 {
			return "", fmt.Errorf("res-nsaddr: invalid DNS port %q", port)
		}
		if portNum == 0 {
			portNum = defaultDNSPort
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(portNum)), nil
}

func splitResNSAddr(value string) (host, port string, err error) {
	if strings.HasPrefix(value, "[") {
		end := strings.IndexByte(value, ']')
		if end < 0 {
			return "", "", fmt.Errorf("res-nsaddr: missing closing bracket in %q", value)
		}
		host = value[1:end]
		switch rest := value[end+1:]; {
		case rest == "":
			return host, "", nil
		case strings.HasPrefix(rest, ":") && len(rest) > 1:
			return host, rest[1:], nil
		default:
			return "", "", fmt.Errorf("res-nsaddr: invalid bracketed nameserver %q", value)
		}
	}

	if addr, parseErr := netip.ParseAddr(value); parseErr == nil {
		return addr.String(), "", nil
	}
	if strings.Count(value, ":") == 1 {
		host, port, err = net.SplitHostPort(value)
		if err != nil || host == "" || port == "" {
			return "", "", fmt.Errorf("res-nsaddr: invalid nameserver %q (want ipv4[:port] or hostname[:port])", value)
		}
		return host, port, nil
	}
	if strings.Contains(value, ":") {
		return "", "", fmt.Errorf("res-nsaddr: IPv6 nameserver is not supported (classic TYPE_IP4SOCK)")
	}
	return value, "", nil
}

func validateResNSHost(host string) error {
	if addr, err := netip.ParseAddr(host); err == nil {
		if !addr.Is4() {
			return fmt.Errorf("res-nsaddr: IPv6 nameserver is not supported (classic TYPE_IP4SOCK)")
		}
		return nil
	}

	name := strings.TrimSuffix(host, ".")
	if name == "" || len(name) > 253 {
		return fmt.Errorf("res-nsaddr: invalid nameserver host %q", host)
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("res-nsaddr: invalid nameserver host %q", host)
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
				(c < '0' || c > '9') && c != '-' && c != '_' {
				return fmt.Errorf("res-nsaddr: invalid nameserver host %q", host)
			}
		}
	}
	return nil
}

// IPHint is the net.Resolver.LookupIP network for a connect/listen network
// ("tcp4"/"udp6"/"sctp" → "ip4"/"ip6"/"ip").
func IPHint(network string) string {
	switch {
	case strings.HasSuffix(network, "4"):
		return "ip4"
	case strings.HasSuffix(network, "6"):
		return "ip6"
	default:
		return "ip"
	}
}

// FormatIPForNetwork stringifies ip for Dial/Listen on network.
// IPv4-mapped results of an IPv6 lookup must stay in ::ffff: form so tcp6
// and udp6 do not treat them as AF_INET (net.IP.String prints mapped as dotted
// IPv4).
func FormatIPForNetwork(network string, ip net.IP) string {
	if !WantIPv4(network, ip) {
		if lit, ok := ipv4MappedLiteral(ip); ok {
			return lit
		}
	}
	return ip.String()
}

// WantIPv4 reports whether ip is used as AF_INET on network.
// IPv4-mapped addresses from an ip6 lookup stay AF_INET6 (classic
// AI_V4MAPPED / sockaddr_in6).
func WantIPv4(network string, ip net.IP) bool {
	if forcedIPv6Network(network) {
		return false
	}
	if forcedIPv4Network(network) {
		return true
	}
	return ip.To4() != nil
}

func ipv4MappedLiteral(ip net.IP) (string, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return "", false
	}
	return fmt.Sprintf("::ffff:%s", ip4.String()), true
}

func ipv4MappedAddrs(ips []net.IP) []net.IP {
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		mapped := make(net.IP, net.IPv6len)
		mapped[10] = 0xff
		mapped[11] = 0xff
		copy(mapped[12:], ip4)
		out = append(out, mapped)
	}
	return out
}

func v4mappedEnabled(s parse.Spec) bool {
	// POSIX AI_V4MAPPED applies only with AF_INET6. glibc and the classic
	// man page default it on for IPv6 socat addresses ("the default is 1").
	// C does not set the bit itself. Match that default unless ai-v4mapped=0.
	if s.HasOption("ai-v4mapped") {
		return s.BoolOption("ai-v4mapped")
	}
	return true
}

func applyAIAddrConfig(s parse.Spec, ips []net.IP) []net.IP {
	if s.HasOption("ai-addrconfig") && s.BoolOption("ai-addrconfig") {
		return filterAIAddrConfig(ips)
	}
	return ips
}

// LookupIP resolves host with the per-address resolver and getaddrinfo flags
// Go can reproduce: AI_V4MAPPED/AI_ALL on ip6, and AI_ADDRCONFIG when set.
// It never mutates net.DefaultResolver. Literals skip DNS.
func LookupIP(ctx context.Context, s parse.Spec, hint, host string) ([]net.IP, error) {
	host = StripBrackets(host)
	if host == "" {
		return nil, nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	if strings.Contains(host, "%") {
		if addr, err := netip.ParseAddr(host); err == nil {
			return []net.IP{addr.AsSlice()}, nil
		}
	}

	resolver := LookupResolver(s)
	if hint == "ip6" && v4mappedEnabled(s) {
		return lookupIPv6Mapped(ctx, s, resolver, host)
	}
	ips, err := resolver.LookupIP(ctx, hint, host)
	if err != nil {
		return nil, err
	}
	return applyAIAddrConfig(s, ips), nil
}

func lookupIPv6Mapped(ctx context.Context, s parse.Spec, resolver *net.Resolver, host string) ([]net.IP, error) {
	v6, err6 := resolver.LookupIP(ctx, "ip6", host)
	if err6 != nil {
		v6 = nil
	}
	wantAll := s.BoolOption("ai-all")
	if !wantAll && len(v6) > 0 {
		return applyAIAddrConfig(s, v6), nil
	}
	v4, err4 := resolver.LookupIP(ctx, "ip4", host)
	if err4 != nil {
		if len(v6) > 0 {
			return applyAIAddrConfig(s, v6), nil
		}
		if err6 != nil {
			return nil, err6
		}
		return nil, err4
	}
	mapped := ipv4MappedAddrs(v4)
	var ips []net.IP
	if wantAll {
		ips = append(v6, mapped...)
	} else {
		ips = mapped
	}
	ips = applyAIAddrConfig(s, ips)
	if len(ips) == 0 {
		return nil, fmt.Errorf("lookup %s: no addresses", host)
	}
	return ips, nil
}

// ResolveIPHost resolves one host with the resolver scoped to s. Literals are
// returned without a lookup, preserving the classic no-DNS literal fast path.
func ResolveIPHost(ctx context.Context, s parse.Spec, network, host string) (string, error) {
	host = StripBrackets(host)
	if host == "" {
		return host, nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return FormatIPForNetwork(network, ip), nil
	}
	if strings.Contains(host, "%") {
		if addr, err := netip.ParseAddr(host); err == nil {
			return addr.String(), nil
		}
	}

	hint := IPHint(network)
	ips, err := LookupIP(ctx, s, hint, host)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("resolve %s: no addresses", host)
	}
	return FormatIPForNetwork(network, ips[0]), nil
}

// ResolveUDPAddr is net.ResolveUDPAddr with per-address DNS selection and
// context cancellation. Literal addresses never reach the selected DNS server.
func ResolveUDPAddr(ctx context.Context, s parse.Spec, network, address string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	resolved, err := ResolveIPHost(ctx, s, network, host)
	if err != nil {
		return nil, err
	}
	return net.ResolveUDPAddr(network, net.JoinHostPort(resolved, port))
}
