package xio

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
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
// IPv4-mapped addresses stringify as dotted IPv4 because Go's net package
// unmaps them (IP.String, Dial("tcp6")); connect uses AF_INET for those
// results (README Intentional differences).
func FormatIPForNetwork(network string, ip net.IP) string {
	if WantIPv4(network, ip) {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String()
		}
	}
	return ip.String()
}

// WantIPv4 reports whether ip is used as AF_INET on network.
// IPv4-mapped AI_V4MAPPED results have a To4() form; Go cannot Dial them on
// *6 networks ("no suitable address found"), so they stay AF_INET.
func WantIPv4(network string, ip net.IP) bool {
	if ip.To4() != nil {
		return true
	}
	return forcedIPv4Network(network)
}

// DialNetwork is the net.Dial/Listen network for ip.
// Hostname AI_V4MAPPED results are IPv4-mapped; Go cannot use them on tcp6,
// udp6, ip6, or sctp6, so those become the IPv4 network (README Intentional
// differences). Literals keep the caller network; callers must not pass an
// IPv4 literal on a *6 network through this helper.
func DialNetwork(network string, ip net.IP) string {
	base := dialNetworkBase(network)
	if base == "" {
		return network
	}
	if WantIPv4(network, ip) {
		return base + "4"
	}
	return base + "6"
}

func dialNetworkBase(network string) string {
	switch {
	case strings.HasPrefix(network, "tcp"):
		return "tcp"
	case strings.HasPrefix(network, "udp"):
		return "udp"
	case strings.HasPrefix(network, "sctp"):
		return "sctp"
	case strings.HasPrefix(network, "ip"):
		return "ip"
	default:
		return ""
	}
}

// MatchLocalPacketAddr rewrites an unspecified local UDP bind to the family of
// network after DialNetwork switches *6 to *4 for a mapped result.
func MatchLocalPacketAddr(network string, laddr net.Addr) (net.Addr, error) {
	if laddr == nil {
		return nil, nil
	}
	ua, ok := laddr.(*net.UDPAddr)
	if !ok {
		return laddr, nil
	}
	out := *ua
	if ua.IP != nil {
		out.IP = append(net.IP(nil), ua.IP...)
	}
	want4 := strings.HasSuffix(network, "4")
	if out.IP == nil || out.IP.IsUnspecified() {
		if want4 {
			out.IP = net.IPv4zero
		} else if strings.HasSuffix(network, "6") {
			out.IP = net.IPv6zero
		}
		return &out, nil
	}
	got4 := out.IP.To4() != nil
	if got4 != want4 && (strings.HasSuffix(network, "4") || strings.HasSuffix(network, "6")) {
		return nil, fmt.Errorf("bind: address family mismatch")
	}
	return &out, nil
}

// LookupDialIP resolves host for network. Literals keep network. Hostnames
// may switch *6 to *4 after AI_V4MAPPED (README Intentional differences).
func LookupDialIP(ctx context.Context, s parse.Spec, network, host string) (string, net.IP, error) {
	host = StripBrackets(host)
	if host == "" {
		return network, nil, nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return network, ip, nil
	}
	ips, err := LookupIP(ctx, s, IPHint(network), host)
	if err != nil {
		return "", nil, err
	}
	if len(ips) == 0 {
		return "", nil, fmt.Errorf("resolve %s: no addresses", host)
	}
	ip := ips[0]
	return DialNetwork(network, ip), ip, nil
}

// PacketNetworkForHost returns the packet/dial network for a hostname lookup.
// QUIC and PROXY HTTP/3 call this before binding UDP so an AI_V4MAPPED result
// can switch udp6 to udp4. Literals keep network.
func PacketNetworkForHost(ctx context.Context, s parse.Spec, network, host string) (string, error) {
	netw, _, err := LookupDialIP(ctx, s, network, host)
	return netw, err
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
	// Official C never ORs AI_V4MAPPED (xiogetaddrinfo in xio-ip.c at
	// tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
	// af5388c898c7bb60997935aee93c223deba60c4a is unchanged). The man page
	// says IPv6 addresses default it to 1. Follow C for drop-in runtime
	// parity: off unless ai-v4mapped is set truthily.
	return s.HasOption("ai-v4mapped") && s.BoolOption("ai-v4mapped")
}

func addrconfigEnabled(s parse.Spec, hint string) bool {
	// Classic CHANGES / xio-ip.c: AI_ADDRCONFIG defaults on when the
	// resolver has no address-family hint (PF_UNSPEC). ai-addrconfig=0
	// clears it; a present truthy value sets it for any hint.
	if s.HasOption("ai-addrconfig") {
		return s.BoolOption("ai-addrconfig")
	}
	return hint == "ip"
}

func applyAIAddrConfig(s parse.Spec, hint string, ips []net.IP) []net.IP {
	if addrconfigEnabled(s, hint) {
		return filterAIAddrConfig(ips)
	}
	return ips
}

func preferIPv6First(ips []net.IP) {
	sort.SliceStable(ips, func(i, j int) bool {
		return ips[i].To4() == nil && ips[j].To4() != nil
	})
}

// LookupIP resolves host with the per-address resolver and getaddrinfo flags
// Go can reproduce: AI_V4MAPPED/AI_ALL on ip6 when set, AI_ADDRCONFIG (default
// on for hint "ip"), and AI_PASSIVE IPv6-first order on dual-stack lookups.
// It never mutates net.DefaultResolver. Literals skip DNS.
//
// IPv4-mapped results are dialed as AF_INET: Go unmaps ::ffff: addresses
// (README Intentional differences / ai-v4mapped dial family).
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
	var (
		ips []net.IP
		err error
	)
	if hint == "ip6" && v4mappedEnabled(s) {
		ips, err = lookupIPv6Mapped(ctx, s, resolver, host)
	} else {
		ips, err = resolver.LookupIP(ctx, hint, host)
		if err == nil {
			ips = applyAIAddrConfig(s, hint, ips)
		}
	}
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("lookup %s: no addresses", host)
	}
	if hint == "ip" && s.BoolOption("ai-passive") && len(ips) > 1 {
		preferIPv6First(ips)
	}
	return ips, nil
}

func lookupIPv6Mapped(ctx context.Context, s parse.Spec, resolver *net.Resolver, host string) ([]net.IP, error) {
	v6, err6 := resolver.LookupIP(ctx, "ip6", host)
	if err6 != nil {
		v6 = nil
	}
	wantAll := s.BoolOption("ai-all")
	if !wantAll && len(v6) > 0 {
		return finishMappedLookup(s, host, v6)
	}
	v4, err4 := resolver.LookupIP(ctx, "ip4", host)
	if err4 != nil {
		if len(v6) > 0 {
			return finishMappedLookup(s, host, v6)
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
	return finishMappedLookup(s, host, ips)
}

func finishMappedLookup(s parse.Spec, host string, ips []net.IP) ([]net.IP, error) {
	ips = applyAIAddrConfig(s, "ip6", ips)
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
