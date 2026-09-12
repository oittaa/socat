package xio

import (
	"github.com/oittaa/socat/internal/addrconfig"
)

// Descriptor lifecycle options apply after open, then late. ApplyFDOptions
// owns already-open files. Fd numbers are not cached. OPEN/FILE/CREATE/GOPEN
// consume perm= as open(2) mode so umask applies. Windows hides and rejects
// ioctl-* and cloexec.

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

func hasConfiguredFDActions(config addrconfig.File, skip FDSkip) bool {
	for _, action := range config.Actions {
		switch action.Kind {
		case addrconfig.FileActionPerm:
			if !skip.Perm {
				return true
			}
		case addrconfig.FileActionUser:
			if !skip.User {
				return true
			}
		case addrconfig.FileActionGroup:
			if !skip.Group {
				return true
			}
		case addrconfig.FileActionAppend:
			if !skip.Append {
				return true
			}
		case addrconfig.FileActionAsync:
			if !skip.Async {
				return true
			}
		case addrconfig.FileActionFlock, addrconfig.FileActionTruncate,
			addrconfig.FileActionSeekStart, addrconfig.FileActionSeekCurrent,
			addrconfig.FileActionSeekEnd, addrconfig.FileActionPermLate,
			addrconfig.FileActionUserLate, addrconfig.FileActionGroupLate,
			addrconfig.FileActionCloexec, addrconfig.FileActionNoAtime,
			addrconfig.FileActionPipeSize, addrconfig.FileActionFSFlag,
			addrconfig.FileActionIoctl, addrconfig.FileActionNoInherit:
			return true
		}
	}
	return false
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
