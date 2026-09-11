//go:build darwin || windows

package xio

import (
	"fmt"
	"os"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

func optionBoolAny(s parse.Spec, names ...string) (bool, bool) {
	value, ok := unsupportedOptionValueAny(s, names...)
	if !ok {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "0", "false", "no", "off":
		return false, true
	default:
		return true, true
	}
}

func ApplyFDOptions(f *os.File, s parse.Spec) error {
	return ApplyFDOptionsSkip(f, s, FDSkip{})
}

func ApplyFDOptionsSkip(f *os.File, s parse.Spec, skip FDSkip) error {
	if enabled, ok := optionBoolAny(s, "o-noatime", "noatime"); ok && enabled {
		return fmt.Errorf("o-noatime: not supported on this platform")
	}
	for _, op := range linuxExtFSFlagOps(s) {
		if op.enable {
			return fmt.Errorf("%s: not supported on this platform", op.name)
		}
	}
	if _, ok := unsupportedOptionValueAny(s, "f-setpipe-sz", "pipesz"); ok {
		return fmt.Errorf("f-setpipe-sz: not supported on this platform")
	}
	return applyFDLifecycleToFile(f, s, skip)
}

// unsupportedOptionValueAny is restricted to the Darwin/Windows rejection
// path. Descriptor actions move to prepared configuration before that path is
// removed; it is not an execution accessor for supported resource owners.
func unsupportedOptionValueAny(s parse.Spec, names ...string) (string, bool) {
	for i := len(s.Options) - 1; i >= 0; i-- {
		for _, name := range names {
			if !strings.EqualFold(s.Options[i].Name, name) {
				continue
			}
			if !s.Options[i].Has {
				return "1", true
			}
			return s.Options[i].Value, true
		}
	}
	return "", false
}

type linuxExtFSFlagOp struct {
	name   string
	mask   int
	enable bool
}

func linuxExtFSFlagOps(s parse.Spec) []linuxExtFSFlagOp {
	var out []linuxExtFSFlagOp
	for _, o := range s.Options {
		canon := parse.CanonicalOptionName(o.Name)
		mask, ok := linuxExtFSFlagMasks[canon]
		if !ok {
			continue
		}
		out = append(out, linuxExtFSFlagOp{name: canon, mask: mask, enable: o.Active()})
	}
	return out
}
