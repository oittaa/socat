package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/optionmeta"
	"github.com/oittaa/socat/internal/parse"
)

const isolationUnsupportedReason = "process-wide credentials/root changes require process isolation"

// RejectUnsupportedIsolation fails when a spec requests process-wide
// credential or root changes. Those require process isolation and are not
// implemented.
func RejectUnsupportedIsolation(s parse.Spec) error {
	typ := s.Type
	if typ == "" {
		typ = "address"
	}
	for _, option := range s.Options {
		if _, ok := isolationCanonicalName(option); !ok {
			continue
		}
		return fmt.Errorf("%s: option %q is not supported (%s)", typ, option.OriginalSpelling(), isolationUnsupportedReason)
	}
	return nil
}

func isolationCanonicalName(option parse.Option) (string, bool) {
	if name, ok := optionmeta.IsolationCanonical(parse.CanonicalOptionName(option.OriginalSpelling())); ok {
		return name, true
	}
	if name, ok := optionmeta.IsolationCanonical(parse.CanonicalOptionName(option.Name)); ok {
		return name, true
	}
	return "", false
}
