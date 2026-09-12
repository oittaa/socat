// Package wsopen implements WS / WSS connect and listen.
// The byte relay carries binary WebSocket messages as a stream.
package wsopen

import (
	"fmt"

	"github.com/oittaa/socat/internal/addrconfig"
)

// wsTarget extracts host, port, and URL path from prepared WS/WSS settings.
func wsTarget(s addrconfig.Address, listen bool) (host, port, path string, err error) {
	if s.TLS.WSPath.Set {
		path = s.TLS.WSPath.Value
	}
	if listen {
		if !s.Network.ListenSet || s.Network.ListenPort.Empty() {
			return "", "", "", fmt.Errorf("%s requires port", s.Type)
		}
		port = s.Network.ListenPort.Text()
	} else {
		if !s.Network.TargetSet || s.Network.Target.Empty() || s.Network.TargetPort.Empty() {
			return "", "", "", fmt.Errorf("%s requires host and port", s.Type)
		}
		host = s.Network.Target.Original()
		port = s.Network.TargetPort.Text()
	}
	return host, port, path, nil
}
