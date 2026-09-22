package xio

import (
	"strings"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

// ParamCount is how many positional parameters an address accepts.
// Max < 0 means there is no upper bound.
type ParamCount struct {
	Min, Max int
	explicit bool
}

// Params records an address's accepted positional parameter count.
// Max < 0 means there is no upper bound. Help syntax is not consulted.
func Params(min, max int) ParamCount {
	return ParamCount{Min: min, Max: max, explicit: true}
}

func (p ParamCount) allows(n int) bool {
	if n < p.Min {
		return false
	}
	return p.Max < 0 || n <= p.Max
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
