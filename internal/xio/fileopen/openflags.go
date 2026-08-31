package fileopen

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

// openFlag is one open(2) bit (o-direct, o-sync, …) or async (O_ASYNC),
// OR'd into the open flags.
type openFlag struct {
	name      string
	bit       int
	supported bool
}

var openFlagByName = make(map[string]openFlag, len(openFlagTable))

func init() {
	for _, f := range openFlagTable {
		openFlagByName[f.name] = f
	}
}

// applyOpenFlags ORs o-direct / o-sync / async bits into open flags in
// command-line order. Order matters for overlapping Linux O_SYNC/O_DSYNC/
// O_RSYNC. Bare flag stores 1; =0 still applies (clears the bit).
func applyOpenFlags(s parse.Spec, flags int) (int, error) {
	for _, o := range s.Options {
		f, ok := openFlagByName[parse.CanonicalOptionName(o.Name)]
		if !ok {
			continue
		}
		enable := o.Active()
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

// rejectUnnamedPIPEOpenFlags rejects enabled o-direct / o-sync / … on
// unnamed PIPE: pipe(2) has no open(2) phase, so those flags would be
// dropped. async is applied later with F_SETFL.
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

// GOPEN delegates an existing socket path to the UNIX address, which has
// no open(2) phase. Reject enabled o-direct / o-sync / … instead of
// silently dropping them. async remains meaningful on the connected socket.
func rejectGOPENSocketOpenFlags(s parse.Spec) error {
	for _, o := range s.Options {
		f, ok := openFlagByName[parse.CanonicalOptionName(o.Name)]
		if !ok || f.name == "async" || !o.Active() {
			continue
		}
		if !f.supported {
			return fmt.Errorf("%s: not supported on this platform", o.OriginalSpelling())
		}
		return fmt.Errorf("%s: not supported when GOPEN resolves to a socket", o.OriginalSpelling())
	}
	return nil
}
