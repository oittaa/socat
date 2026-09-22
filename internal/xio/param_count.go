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
	name := typedAddressName(spec, desc.Name)
	return addrconfig.WrongParameterCount(name, n, desc.Params.Min, desc.Params.Max, usageSyntax(name, desc.Name, desc.Syntax))
}

// typedAddressName keeps the keyword spelling from the original address.
func typedAddressName(spec parse.Spec, fallback string) string {
	raw := strings.TrimSpace(spec.Raw)
	if raw != "" {
		end := len(raw)
		for i := 0; i < len(raw); i++ {
			if raw[i] == ':' || raw[i] == ',' {
				end = i
				break
			}
		}
		token := raw[:end]
		if token != "" && (spec.Type == "" || strings.EqualFold(token, spec.Type)) {
			return token
		}
	}
	if strings.TrimSpace(spec.Type) != "" {
		return spec.Type
	}
	return fallback
}

// usageSyntax is the help form with the keyword as the user typed it.
func usageSyntax(typed, canonical, syntax string) string {
	if syntax == "" {
		return typed
	}
	if canonical != "" && len(syntax) >= len(canonical) && strings.EqualFold(syntax[:len(canonical)], canonical) {
		return typed + syntax[len(canonical):]
	}
	return syntax
}
