package addrconfig

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const defaultDNSPort = 53

// ParseResNSAddr validates res-nsaddr and returns a dialable host:port.
// Accepts an IPv4 address or hostname plus an optional port. IPv6
// nameserver literals are rejected.
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
		return "", "", fmt.Errorf("res-nsaddr: IPv6 nameserver is not supported")
	}
	return value, "", nil
}

func validateResNSHost(host string) error {
	if addr, err := netip.ParseAddr(host); err == nil {
		if !addr.Is4() {
			return fmt.Errorf("res-nsaddr: IPv6 nameserver is not supported")
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
