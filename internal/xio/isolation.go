package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

const isolationUnsupportedReason = "process-wide credentials/root changes require process isolation"

// isolationOptionCanonical is the documented or classified name for process-wide
// credential and chroot options. They are recognized so callers get this
// reason instead of "unknown option"; they are not implemented and not advertised.
var isolationOptionCanonical = map[string]string{
	"chroot":            "chroot",
	"chroot-early":      "chroot-early",
	"setuid":            "setuid",
	"setuid-early":      "setuid-early",
	"setgid":            "setgid",
	"setgid-early":      "setgid-early",
	"substuser":         "substuser",
	"su":                "substuser",
	"substuser-delayed": "substuser-delayed",
	"su-d":              "substuser-delayed",
	"substuser-early":   "substuser-early",
}

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
	if name, ok := isolationOptionCanonical[parse.CanonicalOptionName(option.OriginalSpelling())]; ok {
		return name, true
	}
	if name, ok := isolationOptionCanonical[parse.CanonicalOptionName(option.Name)]; ok {
		return name, true
	}
	return "", false
}
