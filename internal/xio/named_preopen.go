package xio

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// ApplyNamedPreopen applies classic PH_PREOPEN NAMED options in command-line
// order (applyopts_named in xio-named.c, tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same tree).
//
// Despite the "-early" names, perm-early / user-early / group-early are
// PH_PREOPEN, not PH_EARLY. They chmod/chown the existing filesystem path
// before open. unlink/delete/remove at this phase honor documented TYPE_BOOL
// (unlink=0 does not delete). Classic applyopts_named unlinks on presence;
// that is an intentional documented difference.
//
// Callers must invoke this only when the name exists. Classic
// _xioopen_named_early drops PH_PREOPEN when the path is missing so chmod,
// chown, and unlink are not attempted on a non-existent name. UNIX bind
// paths call ApplyNamedAfterBind once the directory entry exists.
func ApplyNamedPreopen(path string, s parse.Spec) error {
	for _, o := range s.Options {
		switch parse.CanonicalOptionName(o.Name) {
		case "perm-early":
			mode, err := parseModeT("perm-early", o.Value)
			if err != nil {
				return err
			}
			if err := os.Chmod(path, mode); err != nil {
				return fmt.Errorf("chmod %s: %w", path, err)
			}
		case "user-early":
			uid, has, err := resolveUID(o.Value)
			if err != nil {
				return err
			}
			if !has {
				continue
			}
			if err := os.Chown(path, uid, -1); err != nil {
				return fmt.Errorf("chown %s: %w", path, err)
			}
		case "group-early":
			gid, has, err := resolveGID(o.Value)
			if err != nil {
				return err
			}
			if !has {
				continue
			}
			if err := os.Chown(path, -1, gid); err != nil {
				return fmt.Errorf("chown %s: %w", path, err)
			}
		case "unlink":
			// Same classic applyopts_named presence bug as unlink=0; honor the bool.
			if !optionEnabled(o) {
				continue
			}
			if err := Unlink(path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("unlink %s: %w", path, err)
			}
		}
	}
	return nil
}

// ApplyNamedAfterBind applies GROUP_NAMED options to a filesystem UNIX
// socket after bind, matching classic xio-listen.c / xio-socket.c
// (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same tree):
// applyopts_named(PH_FD) then applyopts_named(PH_PREOPEN).
//
// Classic xio-unix.c documents that perm-early is useless before bind
// because the directory entry does not exist yet; after bind it chmods the
// new socket. PH_PREOPEN after PH_FD means perm-early wins over perm=.
// unlink= at this phase would remove the just-bound name (classic would
// too). Abstract names have no filesystem entry and are skipped.
func ApplyNamedAfterBind(path string, s parse.Spec, f *os.File) error {
	if path == "" || IsAbstract(path) {
		return nil
	}
	if err := ApplyNamedAttrs(path, s, f); err != nil {
		return err
	}
	return ApplyNamedPreopen(path, s)
}

func parseModeT(name, v string) (os.FileMode, error) {
	m, err := strconv.ParseUint(v, 8, 32)
	if err != nil || m > 0o7777 {
		return 0, fmt.Errorf("invalid %s %q", name, v)
	}
	return UnixModeToFileMode(uint32(m)), nil
}

func optionEnabled(o parse.Option) bool {
	if !o.Has {
		return true
	}
	v := strings.ToLower(strings.TrimSpace(o.Value))
	if v == "" {
		return false
	}
	return v != "0" && v != "false" && v != "no" && v != "off"
}
