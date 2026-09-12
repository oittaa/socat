package addrconfig

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const defaultDNSPort = 53

// NameServer is the decoded res-nsaddr value. The nameserver host is resolved
// when the resolver dials.
type NameServer struct {
	Set  bool
	Host HostTarget
	Port PortTarget
}

// String is the decoded host:port spelling.
func (n NameServer) String() string {
	return n.DialHostPort()
}

// DialHostPort is host:port for net.Dialer, using the already decoded port.
func (n NameServer) DialHostPort() string {
	if !n.Set {
		return ""
	}
	port := n.Port.Text()
	if port == "" {
		port = strconv.Itoa(defaultDNSPort)
	}
	return net.JoinHostPort(n.Host.String(), port)
}

// ParseResNSAddr validates res-nsaddr and returns the static host and port.
// Accepts an IPv4 address or hostname plus an optional port. IPv6
// nameserver literals are rejected. Service names stay for runtime lookup.
func ParseResNSAddr(value string) (NameServer, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return NameServer{}, fmt.Errorf("res-nsaddr: nameserver address is empty")
	}

	host, port, err := splitResNSAddr(value)
	if err != nil {
		return NameServer{}, err
	}
	if err := validateResNSHost(host); err != nil {
		return NameServer{}, err
	}

	ns := NameServer{Set: true, Host: targetFromText(host)}
	if port == "" {
		ns.Port = PortTarget{Number: defaultDNSPort, Numeric: true}
		return ns, nil
	}
	portNum, err := strconv.Atoi(port)
	if err == nil {
		if portNum < 0 || portNum > 65535 {
			return NameServer{}, fmt.Errorf("res-nsaddr: invalid DNS port %q", port)
		}
		if portNum == 0 {
			portNum = defaultDNSPort
		}
		ns.Port = PortTarget{Number: uint16(portNum), Numeric: true, Service: port}
		return ns, nil
	}
	ns.Port = PortTarget{Service: port}
	return ns, nil
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
