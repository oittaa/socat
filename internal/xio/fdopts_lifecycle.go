package xio

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// Descriptor lifecycle options from classic xio-fd.c / applyopt_spec /
// applyopt_fcntl (https://repo.or.cz/socat.git tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a has the same option records):
//
//   - append / o-append: GROUP_FD|GROUP_OPEN, PH_LATE, TYPE_BOOL, OFUNC_FCNTL
//     F_SETFL O_APPEND. applyopt_fcntl GETFL then flag|=O_APPEND or
//     flag&=~O_APPEND, so append=0 clears the bit. Bare append is true.
//   - perm / mode: GROUP_FD|GROUP_NAMED, PH_FD, fchmod(2) on the descriptor.
//     Classic xioopts.c IF_ANY("mode", &opt_perm).
//   - user / uid / owner, group / gid: GROUP_FD|GROUP_NAMED, PH_FD, fchown(2).
//   - ftruncate / truncate / ftruncate32 / ftruncate64: GROUP_REG, PH_LATE,
//     ftruncate(2). Fail when the fd is not a regular file.
//
// Named OPEN/FILE/CREATE/GOPEN still consume perm= as open(2) mode (classic
// retropt_modet) so umask applies; those types skip fchmod here. Their
// ftruncate stays on the named-file open path to avoid truncating twice and
// to keep Windows working.

func hasFDLifecycleOptions(s parse.Spec) bool {
	if s.HasOption("append") {
		return true
	}
	if _, ok := lastLifecycleOption(s, "ftruncate", "truncate", "ftruncate32", "ftruncate64"); ok {
		return true
	}
	if skipDescriptorOwnerOpts(s.Type) {
		return false
	}
	if _, ok := lastLifecycleOption(s, "perm", "mode"); ok {
		return true
	}
	if _, ok := lastLifecycleOption(s, "user", "uid", "owner"); ok {
		return true
	}
	if _, ok := lastLifecycleOption(s, "group", "gid"); ok {
		return true
	}
	return false
}

// skipDescriptorOwnerOpts reports address types that already consume perm=/
// user=/group= as create mode or named chmod/chown (classic retropt_modet /
// ApplyNamedAttrs / ApplyNamedAfterBind). Applying fchmod here would undo
// umask on regular files and fchmod a PTY master instead of the slave.
// Named UNIX*/ABSTRACT* keep path chmod; Darwin fchmod on those sockets may
// still return EINVAL. Anonymous sockets (FD/TCP/STDIO/EXEC) still apply
// fchmod/fchown and must propagate EINVAL — do not swallow it.
func skipDescriptorOwnerOpts(addrType string) bool {
	t := strings.ToUpper(addrType)
	switch t {
	case "OPEN", "FILE", "CREATE", "CREAT", "GOPEN", "PIPE", "FIFO", "ECHO", "PTY":
		return true
	}
	if strings.HasPrefix(t, "UNIX") || strings.HasPrefix(t, "ABSTRACT") {
		return true
	}
	return false
}

func skipNamedFileFtruncate(addrType string) bool {
	switch strings.ToUpper(addrType) {
	case "OPEN", "FILE", "CREATE", "CREAT", "GOPEN":
		return true
	default:
		return false
	}
}

// lastLifecycleOption returns the last command-line option whose canonical
// name matches any of names (classic last-option-wins across aliases).
func lastLifecycleOption(s parse.Spec, names ...string) (parse.Option, bool) {
	want := make(map[string]struct{}, len(names))
	for _, name := range names {
		want[parse.CanonicalOptionName(name)] = struct{}{}
	}
	for i := len(s.Options) - 1; i >= 0; i-- {
		n := parse.CanonicalOptionName(s.Options[i].Name)
		if _, ok := want[n]; ok {
			return s.Options[i], true
		}
	}
	return parse.Option{}, false
}

func parseFtruncateLength(s parse.Spec) (int64, bool, error) {
	o, ok := lastLifecycleOption(s, "ftruncate", "truncate", "ftruncate32", "ftruncate64")
	if !ok {
		return 0, false, nil
	}
	name := o.OriginalSpelling()
	if !o.Has {
		return 0, true, fmt.Errorf("%s: invalid value %q", name, o.Value)
	}
	n, err := strconv.ParseInt(strings.TrimSpace(o.Value), 0, 64)
	if err != nil || n < 0 {
		return 0, true, fmt.Errorf("%s: invalid value %q", name, o.Value)
	}
	return n, true, nil
}
