package xio

import (
	"strings"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

// ParamCount is how many positional parameters an address accepts.
// Max < 0 means there is no upper bound.
type ParamCount struct {
	Min int
	Max int
}

func (p ParamCount) allows(n int) bool {
	if n < p.Min {
		return false
	}
	return p.Max < 0 || n <= p.Max
}

// paramCountFor derives the accepted parameter count from the address
// syntax. Brackets mark an optional parameter (PIPE[:<filename>]).
func paramCountFor(name, syntax string) ParamCount {
	switch name {
	case "ECHO":
		// ECHO is the same address as PIPE, including its optional filename.
		return ParamCount{Min: 0, Max: 1}
	case "SOCKS5", "SOCKS5-CONNECT", "SOCKS5-LISTEN", "SOCKS5-BIND":
		// Optional socks-port: server:host:port or server:socks-port:host:port.
		return ParamCount{Min: 3, Max: 4}
	case "WS", "WS-CONNECT", "WSS", "WSS-CONNECT":
		// Parameters after host and port are URL path segments.
		return ParamCount{Min: 2, Max: -1}
	case "WS-LISTEN", "WS-L", "WSS-LISTEN", "WSS-L":
		return ParamCount{Min: 1, Max: -1}
	default:
		min, max := boundsFromSyntax(syntax)
		return ParamCount{Min: min, Max: max}
	}
}

func boundsFromSyntax(syntax string) (min, max int) {
	i := strings.IndexAny(syntax, ":[")
	if i < 0 {
		return 0, 0
	}
	depth := 0
	for ; i < len(syntax); i++ {
		switch syntax[i] {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case ':':
			max++
			if depth == 0 {
				min++
			}
		}
	}
	return min, max
}

func validateAddressParams(spec parse.Spec, desc AddressDesc) error {
	n := len(spec.Params)
	if desc.Params.allows(n) {
		return nil
	}
	name := spec.Type
	if strings.TrimSpace(name) == "" {
		name = desc.Name
	}
	return addrconfig.WrongParameterCount(name, n, desc.Params.Min, desc.Params.Max)
}
