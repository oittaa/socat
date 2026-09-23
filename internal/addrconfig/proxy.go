package addrconfig

import (
	"fmt"
	"net"
	"strings"
)

// HTTPVersion selects a CONNECT transport.
type HTTPVersion uint8

const (
	HTTPVersion10 HTTPVersion = iota + 1
	HTTPVersion11
	HTTPVersion2
	HTTPVersion3
)

// Proxy holds static HTTP CONNECT and SOCKS settings.
type Proxy struct {
	Server            HostTarget
	Target            HostTarget
	TargetPort        PortTarget
	EndpointsSet      bool
	Port              PortTarget
	PortSet           bool
	HTTPVersion       HTTPVersion
	H2C               OptionalBool
	IgnoreCR          OptionalBool
	Resolve           OptionalBool
	Authorization     OptionalString
	AuthorizationFile OptionalString
	SOCKSPort         PortTarget
	SOCKSPortSet      bool
	SOCKSUser         OptionalString
	SOCKSPassword     OptionalString
}

func decodeHTTPVersion(value string) (HTTPVersion, error) {
	switch strings.TrimSpace(value) {
	case "1.0", "":
		return HTTPVersion10, nil
	case "1.1":
		return HTTPVersion11, nil
	case "2":
		return HTTPVersion2, nil
	case "3":
		return HTTPVersion3, nil
	default:
		return 0, fmt.Errorf("http-version: invalid value %q", value)
	}
}

func decodePROXYPositional(a *Address) error {
	p := a.Params
	var server, host, port string
	switch {
	case len(p) >= 3:
		server, host, port = p[0], p[1], p[2]
	case len(p) == 2:
		h, pt, err := net.SplitHostPort(p[1])
		if err == nil {
			server, host, port = p[0], h, pt
		}
	case len(p) == 1:
		parts := strings.Split(p[0], ":")
		if len(parts) >= 3 {
			server, host, port = parts[0], parts[1], parts[2]
		}
	}
	if server == "" || host == "" || port == "" {
		return fmt.Errorf("%s requires proxy, host, and port", a.Type)
	}
	targetPort, err := portTarget(port)
	if err != nil {
		return err
	}
	a.Proxy.Server = targetFromText(server)
	a.Proxy.Target = targetFromText(host)
	a.Proxy.TargetPort = targetPort
	a.Proxy.EndpointsSet = true
	return nil
}

func decodeSOCKSPositional(d *decoder) error {
	a := &d.Address
	p := a.Params
	var server, host, port, socksPort string
	switch {
	case len(p) >= 4:
		server, socksPort, host, port = p[0], p[1], p[2], p[3]
	case len(p) >= 3:
		server, host, port = p[0], p[1], p[2]
	case len(p) == 2:
		h, pt, err := net.SplitHostPort(p[1])
		if err == nil {
			server, host, port = p[0], h, pt
		}
	}
	if server == "" || host == "" || port == "" {
		return fmt.Errorf("%s requires socks-server, host, and port", a.Type)
	}
	targetPort, err := portTarget(port)
	if err != nil {
		return err
	}
	a.Proxy.Server = targetFromText(server)
	a.Proxy.Target = targetFromText(host)
	a.Proxy.TargetPort = targetPort
	a.Proxy.EndpointsSet = true
	if socksPort != "" {
		parsed, err := portTarget(socksPort)
		if err != nil {
			return err
		}
		d.socksPositionalPort = parsed
		d.socksPositionalPortSet = true
		// An earlier socksport= option already won. An empty option value is
		// filled from this positional port in finishDecode.
		if !a.Proxy.SOCKSPortSet {
			a.Proxy.SOCKSPort = d.socksPositionalPort
			a.Proxy.SOCKSPortSet = true
		}
	}
	return nil
}
