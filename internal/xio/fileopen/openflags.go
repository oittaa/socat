package fileopen

import (
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// openFlag is one classic GROUP_OPEN OFUNC_FLAG bit (xio-file.c) or the mixed
// GROUP_OPEN|GROUP_FD O_ASYNC flag that _xioopen_open ORs into open(2)
// (xio-named.c, tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba;
// official master af5388c898c7bb60997935aee93c223deba60c4a is the same tree).
type openFlag struct {
	name      string
	bit       int
	supported bool
}

// applyOpenFlags applies classic PH_OPEN OFUNC_FLAG bits (and O_ASYNC) in
// command-line order. The order matters for overlapping flags such as Linux
// O_SYNC/O_DSYNC/O_RSYNC, and a false boolean must clear its bit just as
// classic applyopts_flags does.
func applyOpenFlags(s parse.Spec, flags int) (int, error) {
	byName := make(map[string]openFlag, len(openFlagTable))
	for _, f := range openFlagTable {
		byName[f.name] = f
	}
	for _, o := range s.Options {
		f, ok := byName[parse.CanonicalOptionName(o.Name)]
		if !ok {
			continue
		}
		enable := fileOptionEnabled(o)
		if enable && !f.supported {
			return 0, fmt.Errorf("%s: not supported on this platform", o.OriginalSpelling())
		}
		if enable {
			flags |= f.bit
		} else {
			flags &^= f.bit
		}
	}
	return flags, nil
}

func fileOptionEnabled(o parse.Option) bool {
	if !o.Has {
		return true
	}
	v := strings.ToLower(strings.TrimSpace(o.Value))
	if v == "" {
		return false
	}
	return v != "0" && v != "false" && v != "no" && v != "off"
}

// rejectUnnamedPIPEOpenFlags matches classic leftover-option failure: unnamed
// PIPE uses pipe(2), not open(2), so GROUP_OPEN OFUNC_FLAG options are never
// consumed. async is GROUP_FD as well and is applied with F_SETFL at PH_LATE.
func rejectUnnamedPIPEOpenFlags(s parse.Spec) error {
	for _, f := range openFlagTable {
		if f.name == "async" {
			continue
		}
		if !s.BoolOption(f.name) {
			continue
		}
		if !f.supported {
			return fmt.Errorf("%s: not supported on this platform", f.name)
		}
		return fmt.Errorf("%s: not supported on unnamed PIPE", f.name)
	}
	return nil
}

// GOPEN delegates an existing socket path to the UNIX address implementation,
// which has no open(2) phase. Reject enabled pure GROUP_OPEN flags instead of
// silently losing them during that dispatch. async is also GROUP_FD and remains
// meaningful on the connected socket.
func rejectGOPENSocketOpenFlags(s parse.Spec) error {
	for _, o := range s.Options {
		name := parse.CanonicalOptionName(o.Name)
		for _, f := range openFlagTable {
			if f.name != name || f.name == "async" || !fileOptionEnabled(o) {
				continue
			}
			if !f.supported {
				return fmt.Errorf("%s: not supported on this platform", o.OriginalSpelling())
			}
			return fmt.Errorf("%s: not supported when GOPEN resolves to a socket", o.OriginalSpelling())
		}
	}
	return nil
}
