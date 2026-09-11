package xio

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/oittaa/socat/internal/addrconfig"
)

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
func LookupDialIP(ctx context.Context, s addrconfig.Address, network string, host addrconfig.HostTarget) (string, net.IP, error) {
	if host.IsLiteral() {
		return network, host.IP(), nil
	}
	name := host.String()
	if name == "" {
		return network, nil, nil
	}
	ips, err := LookupIP(ctx, s, IPHint(network), name)
	if err != nil {
		return "", nil, err
	}
	if len(ips) == 0 {
		return "", nil, fmt.Errorf("resolve %s: no addresses", name)
	}
	ip := ips[0]
	return DialNetwork(network, ip), ip, nil
}

// PacketNetworkForHost returns the packet/dial network for a hostname lookup.
// QUIC and PROXY HTTP/3 call this before binding UDP so an AI_V4MAPPED result
// can switch udp6 to udp4. Literals keep network.
func PacketNetworkForHost(ctx context.Context, s addrconfig.Address, network string, host addrconfig.HostTarget) (string, error) {
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

func v4mappedEnabled(config addrconfig.Address) bool {
	// Off unless ai-v4mapped is set truthily. The man page says IPv6
	// addresses default it to 1; remaining off unless requested keeps
	// drop-in runtime parity.
	return config.Common.V4Mapped.Value
}

func addrconfigEnabled(config addrconfig.Address, hint string) bool {
	// AI_ADDRCONFIG defaults on when the resolver has no address-family
	// hint. ai-addrconfig=0 clears it; a present truthy value sets it for
	// any hint.
	if config.Common.AddrConfig.Set {
		return config.Common.AddrConfig.Value
	}
	return hint == "ip"
}

func applyAIAddrConfig(config addrconfig.Address, hint string, ips []net.IP) []net.IP {
	if addrconfigEnabled(config, hint) {
		return filterAIAddrConfig(ips)
	}
	return ips
}

func preferIPv6First(ips []net.IP) {
	sort.SliceStable(ips, func(i, j int) bool {
		return ips[i].To4() == nil && ips[j].To4() != nil
	})
}

func ipv6Only(addrs []net.IP) []net.IP {
	out := make([]net.IP, 0, len(addrs))
	for _, ip := range addrs {
		if ip != nil && ip.To4() == nil {
			out = append(out, ip)
		}
	}
	return out
}

// LookupIP resolves host with the per-address resolver and getaddrinfo flags
// Go can reproduce: AI_V4MAPPED/AI_ALL on ip6 when set, AI_ADDRCONFIG (default
// on for hint "ip"), and AI_PASSIVE IPv6-first order on dual-stack lookups.
// It never mutates net.DefaultResolver. Literals skip DNS.
//
// Linux and Darwin cgo resolvers always pass AI_V4MAPPED|AI_ALL. ipv6Only
// drops those implicit mapped results when mapping is off; lookupIPv6Mapped
// rebuilds mapping explicitly when it is on. PreferGo is not forced, so
// macOS system resolution and Linux NSS (mDNS, LDAP, SSSD) stay available.
//
// IPv4-mapped results are dialed as AF_INET: Go unmaps ::ffff: addresses
// (README Intentional differences / ai-v4mapped dial family).
func LookupIP(ctx context.Context, s addrconfig.Address, hint, host string) ([]net.IP, error) {
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
	var ips []net.IP
	var err error
	if hint == "ip6" && v4mappedEnabled(s) {
		ips, err = lookupIPv6Mapped(ctx, s, resolver, host)
	} else {
		ips, err = resolver.LookupIP(ctx, hint, host)
		if err == nil {
			if hint == "ip6" && !v4mappedEnabled(s) {
				ips = ipv6Only(ips)
			}
			ips = applyAIAddrConfig(s, hint, ips)
		}
	}
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("lookup %s: no addresses", host)
	}
	if hint == "ip" && s.Common.Passive.Value && len(ips) > 1 {
		preferIPv6First(ips)
	}
	return ips, nil
}

func lookupIPv6Mapped(ctx context.Context, config addrconfig.Address, resolver *net.Resolver, host string) ([]net.IP, error) {
	v6, err6 := resolver.LookupIP(ctx, "ip6", host)
	if err6 != nil {
		v6 = nil
	} else {
		// Drop IPv4 and IPv4-mapped entries from the AAAA list so a leaky
		// resolver cannot duplicate mapped results when we append A records.
		v6 = ipv6Only(v6)
	}
	wantAll := config.Common.AddrInfoAll.Value
	if !wantAll && len(v6) > 0 {
		return finishMappedLookup(config, host, v6)
	}
	v4, err4 := resolver.LookupIP(ctx, "ip4", host)
	if err4 != nil {
		if len(v6) > 0 {
			return finishMappedLookup(config, host, v6)
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
	return finishMappedLookup(config, host, ips)
}

func finishMappedLookup(config addrconfig.Address, host string, ips []net.IP) ([]net.IP, error) {
	ips = applyAIAddrConfig(config, "ip6", ips)
	if len(ips) == 0 {
		return nil, fmt.Errorf("lookup %s: no addresses", host)
	}
	return ips, nil
}

// ResolveIPTarget resolves one host with the resolver scoped to s. Literals
// skip DNS.
func ResolveIPTarget(ctx context.Context, s addrconfig.Address, network string, host addrconfig.HostTarget) (net.IP, error) {
	if host.IsLiteral() {
		return host.IP(), nil
	}
	name := host.String()
	if name == "" {
		return nil, nil
	}
	if strings.Contains(name, "%") {
		if addr, err := netip.ParseAddr(name); err == nil {
			return addr.AsSlice(), nil
		}
	}
	hint := IPHint(network)
	ips, err := LookupIP(ctx, s, hint, name)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", name, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve %s: no addresses", name)
	}
	return ips[0], nil
}

// ResolveUDPTarget resolves a typed host and port. Literal IPs never reach
// DNS; numeric ports are not parsed again.
func ResolveUDPTarget(ctx context.Context, s addrconfig.Address, network string, host addrconfig.HostTarget, port addrconfig.PortTarget) (*net.UDPAddr, error) {
	n, err := ResolvePort(network, port)
	if err != nil {
		return nil, err
	}
	if host.IsLiteral() {
		return udpAddrFromHost(network, host, n), nil
	}
	_, ip, err := LookupDialIP(ctx, s, network, host)
	if err != nil {
		return nil, err
	}
	if ip == nil {
		return &net.UDPAddr{Port: n}, nil
	}
	return udpAddrFromIP(network, ip, n, ""), nil
}

func udpAddrFromHost(network string, host addrconfig.HostTarget, port int) *net.UDPAddr {
	return udpAddrFromIP(network, host.IP(), port, host.Literal.Zone())
}

func udpAddrFromIP(network string, ip net.IP, port int, zone string) *net.UDPAddr {
	if ip4 := ip.To4(); ip4 != nil && strings.HasSuffix(network, "4") {
		ip = ip4
	}
	return &net.UDPAddr{IP: ip, Port: port, Zone: zone}
}
