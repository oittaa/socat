package xio

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// Descriptor lifecycle options walk the command-line list after open, then
// late. Every occurrence is applied, including aliases. Last-wins
// OptionNamed is not used for applying. ApplyFDOptions owns already-open
// files. Fd numbers are not cached. OPEN/FILE/CREATE/GOPEN consume perm= as
// open(2) mode so umask applies. Windows hides and rejects ioctl-* and cloexec.

// FDSkip names after-open options this descriptor does not own because the
// opener already consumed them (create mode, named chmod, PTY slave, mq_open).
type FDSkip struct {
	Perm, User, Group bool
	Append, Async     bool
}

// FDSkipOwner skips perm/user/group on a descriptor whose owner options were
// applied to a filesystem name, listen socket, or PTY slave.
var FDSkipOwner = FDSkip{Perm: true, User: true, Group: true}

// FDSkipNamedFile is OPEN/FILE/GOPEN: perm/user/group on the path, append and
// async in open(2).
var FDSkipNamedFile = FDSkip{Perm: true, User: true, Group: true, Append: true, Async: true}

// FDSkipCREATE consumes perm as creat(2) mode and O_APPEND at open; user,
// group, and async still apply on the descriptor.
var FDSkipCREATE = FDSkip{Perm: true, Append: true}

// FDSkipPOSIXMQ consumes perm as mq_open(3) mode.
var FDSkipPOSIXMQ = FDSkip{Perm: true}

func (skip FDSkip) owner(name string) bool {
	switch name {
	case "perm":
		return skip.Perm
	case "user":
		return skip.User
	case "group":
		return skip.Group
	default:
		return false
	}
}

// lifecycleSyscallTestHook is invoked immediately before fchmod/fchown/
// F_SETFL/ftruncate (and the Windows ftruncate path). Tests assert
// exactly-once apply after ApplyFDOptions then WrapAfterFD, and command-line
// order of repeated options.
var lifecycleSyscallTestHook func(op string)

func noteLifecycleSyscall(op string) {
	if hook := lifecycleSyscallTestHook; hook != nil {
		hook(op)
	}
}

// InstallLifecycleSyscallHook installs a test observer invoked immediately
// before each lifecycle syscall (F_SETFL, ftruncate, fchmod, fchown, chmod,
// chown). Tests restore the previous hook with the returned function.
func InstallLifecycleSyscallHook(f func(op string)) func() {
	prev := lifecycleSyscallTestHook
	lifecycleSyscallTestHook = f
	return func() { lifecycleSyscallTestHook = prev }
}

// optionPhaseTestHook is invoked at the start of after-open, after-socket,
// after-connect/accept, and late option application. Tests assert ACCEPT-FD
// applies those stages in that order.
var optionPhaseTestHook func(phase string)

func noteOptionPhase(phase string) {
	if hook := optionPhaseTestHook; hook != nil {
		hook(phase)
	}
}

// InstallOptionPhaseHook installs a test observer invoked at the start of
// each option-phase apply. Tests restore the previous hook with the
// returned function.
func InstallOptionPhaseHook(f func(phase string)) func() {
	prev := optionPhaseTestHook
	optionPhaseTestHook = f
	return func() { optionPhaseTestHook = prev }
}

func hasFDLifecycleOptions(s parse.Spec, skip FDSkip) bool {
	if hasPlatformFDLifecycleOptions(s) {
		return true
	}
	for _, o := range s.Options {
		switch parse.CanonicalOptionName(o.Name) {
		case "append":
			if !skip.Append {
				return true
			}
		case "async":
			if !skip.Async {
				return true
			}
		case "ftruncate", "lseek", "seek-cur", "seek-end":
			return true
		case "perm", "user", "group":
			if !skip.owner(parse.CanonicalOptionName(o.Name)) {
				return true
			}
		case "perm-late", "user-late", "group-late":
			return true
		case "flock", "flock-nb", "flock-sh", "flock-sh-nb":
			return true
		case "ioctl-void", "ioctl-int", "ioctl-intp", "ioctl-bin", "ioctl-string":
			return true
		case "cloexec":
			return true
		}
	}
	return false
}

// lastLifecycleOption returns the last command-line option whose canonical
// name matches any of names. Used for lookups that need a single value
// (open-mode, tests); apply walks every occurrence instead.
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

func parseFtruncateOption(o parse.Option) (int64, error) {
	name := o.OriginalSpelling()
	if !o.Has {
		return 0, fmt.Errorf("%s: invalid value %q", name, o.Value)
	}
	n, err := strconv.ParseInt(strings.TrimSpace(o.Value), 0, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s: invalid value %q", name, o.Value)
	}
	return n, nil
}

func parseLseekOffset(o parse.Option) (int64, error) {
	name := o.OriginalSpelling()
	if !o.Has {
		// Missing value defaults to 1 (man page for seek options).
		return 1, nil
	}
	n, err := strconv.ParseInt(strings.TrimSpace(o.Value), 0, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid value %q", name, o.Value)
	}
	return n, nil
}

func requiredLifecycleOptionValue(o parse.Option) (string, error) {
	v := strings.TrimSpace(o.Value)
	if !o.Has || v == "" {
		return "", fmt.Errorf("%s: value required", o.OriginalSpelling())
	}
	return v, nil
}
