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
// Classic TYPE_IP4SOCK accepts an IPv4 address or hostname plus an optional
// port. This port additionally accepts IPv6 literals; an IPv6 port must use
// [addr]:port so an unbracketed literal remains unambiguous.
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
			return "", "", fmt.Errorf("res-nsaddr: invalid nameserver %q (want host[:port] or [ipv6]:port)", value)
		}
		return host, port, nil
	}
	if strings.Contains(value, ":") {
		return "", "", fmt.Errorf("res-nsaddr: invalid IPv6 nameserver %q (use [addr]:port when specifying a port)", value)
	}
	return value, "", nil
}

func validateResNSHost(host string) error {
	if _, err := netip.ParseAddr(host); err == nil {
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

// ResolveIPHost resolves one host with the resolver scoped to s. Literals are
// returned without a lookup, preserving the classic no-DNS literal fast path.
func ResolveIPHost(ctx context.Context, s parse.Spec, network, host string) (string, error) {
	host = StripBrackets(host)
	if host == "" {
		return host, nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	if strings.Contains(host, "%") {
		if addr, err := netip.ParseAddr(host); err == nil {
			return addr.String(), nil
		}
	}

	hint := "ip"
	switch {
	case strings.HasSuffix(network, "4"):
		hint = "ip4"
	case strings.HasSuffix(network, "6"):
		hint = "ip6"
	}
	ips, err := LookupResolver(s).LookupIP(ctx, hint, host)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("resolve %s: no addresses", host)
	}
	return ips[0].String(), nil
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
