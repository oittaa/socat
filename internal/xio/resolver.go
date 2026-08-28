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
