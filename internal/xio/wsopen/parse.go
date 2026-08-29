// Package wsopen implements WS / WSS connect and listen.
// The byte relay uses github.com/coder/websocket NetConn with binary frames.
package wsopen

import (
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// wsTarget extracts host, port, and URL path from a WS/WSS address spec.
// Connect: WS:<host>:<port>[/<path>]
// Listen:  WS-LISTEN:<port>[/<path>]
// path= option overrides a path in the address.
func wsTarget(s parse.Spec, listen bool) (host, port, path string, err error) {
	path = s.OptionValue("path", "")
	if listen {
		if len(s.Params) < 1 || s.Params[0] == "" {
			return "", "", "", fmt.Errorf("%s requires port", s.Type)
		}
		var p string
		port, p = splitPortPath(s.Params[0])
		if path == "" {
			path = p
		}
		if path == "" && len(s.Params) > 1 {
			path = "/" + strings.Join(s.Params[1:], "/")
		}
	} else {
		if len(s.Params) < 2 {
			return "", "", "", fmt.Errorf("%s requires host and port", s.Type)
		}
		host = s.Params[0]
		var p string
		port, p = splitPortPath(s.Params[1])
		if path == "" {
			path = p
		}
		if path == "" && len(s.Params) > 2 {
			path = "/" + strings.Join(s.Params[2:], "/")
		}
	}
	path = normalizeWSPath(path)
	return host, port, path, nil
}

func splitPortPath(s string) (port, path string) {
	i := strings.Index(s, "/")
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i:]
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

func wsScheme(s parse.Spec) string {
	t := strings.ToUpper(s.Type)
	if strings.HasPrefix(t, "WSS") {
		return "wss"
	}
	return "ws"
}
