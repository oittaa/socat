// Package wsopen implements WS / WSS connect and listen.
// The byte relay carries binary WebSocket messages as a stream.
package wsopen

import (
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/addrconfig"
)

// wsTarget extracts host, port, and URL path from prepared WS/WSS settings.
func wsTarget(s addrconfig.Address, listen bool) (host, port, path string, err error) {
	if s.TLS.WSPath.Set {
		path = s.TLS.WSPath.Value
	}
	if listen {
		if !s.Network.ListenSet {
			return "", "", "", fmt.Errorf("%s requires port", s.Type)
		}
		port = s.Network.ListenPort.Text()
	} else {
		if !s.Network.TargetSet {
			return "", "", "", fmt.Errorf("%s requires host and port", s.Type)
		}
		host = s.Network.Target.Original()
		port = s.Network.TargetPort.Text()
	}
	if port == "" {
		if listen {
			return "", "", "", fmt.Errorf("%s requires port", s.Type)
		}
		return "", "", "", fmt.Errorf("%s requires host and port", s.Type)
	}
	return host, port, normalizeWSPath(path), nil
}

func normalizeWSPath(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

func wsScheme(s addrconfig.Address) string {
	t := strings.ToUpper(s.Type)
	if strings.HasPrefix(t, "WSS") {
		return "wss"
	}
	return "ws"
}
