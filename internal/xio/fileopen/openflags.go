package fileopen

import (
	"fmt"

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

// applyOpenFlags ORs classic PH_OPEN OFUNC_FLAG bits (and O_ASYNC) into flags.
// Enabled flags that this platform does not implement error instead of no-op.
func applyOpenFlags(s parse.Spec, flags int) (int, error) {
	for _, f := range openFlagTable {
		if !s.BoolOption(f.name) {
			continue
		}
		if !f.supported {
			return 0, fmt.Errorf("%s: not supported on this platform", f.name)
		}
		flags |= f.bit
	}
	return flags, nil
}

func applyODirectFlag(s parse.Spec, flags int) (int, error) {
	return applyOpenFlags(s, flags)
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
