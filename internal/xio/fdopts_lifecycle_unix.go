//go:build linux || darwin

package xio

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/unix"
)

// fdLifecycleTestHook is invoked each time lifecycle options are applied to
// an fd. Tests use it to observe SetupStream's per-call same-fd dedup.
var fdLifecycleTestHook func(fd int)

// ApplyConfiguredFDOptions applies prepared descriptor actions. Callers that
// crossed PrepareChannel must use this path instead of reparsing Spec options.
func ApplyConfiguredFDOptions(f *os.File, config addrconfig.File, skip FDSkip) error {
	if f == nil || !hasConfiguredFDActions(config, skip) {
		return nil
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var actionErr error
	controlErr := raw.Control(func(fd uintptr) {
		actionErr = applyConfiguredFDOnFD(int(fd), config, skip)
	})
	return errors.Join(controlErr, actionErr)
}

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
			addrconfig.FileActionIoctl:
			return true
		}
	}
	return false
}

func applyConfiguredFDOnFD(fd int, config addrconfig.File, skip FDSkip) error {
	if !hasConfiguredFDActions(config, skip) {
		return nil
	}
	if fdLifecycleTestHook != nil {
		fdLifecycleTestHook(fd)
	}
	noteOptionPhase("FD")
	for _, action := range config.Actions {
		switch action.Kind {
		case addrconfig.FileActionPerm:
			if !skip.Perm {
				if err := applyConfiguredPerm(fd, action); err != nil {
					return err
				}
			}
		case addrconfig.FileActionUser:
			if !skip.User {
				if err := applyConfiguredUser(fd, action); err != nil {
					return err
				}
			}
		case addrconfig.FileActionGroup:
			if !skip.Group {
				if err := applyConfiguredGroup(fd, action); err != nil {
					return err
				}
			}
		case addrconfig.FileActionFlock:
			if action.Enabled {
				if err := applyConfiguredFlock(fd, action); err != nil {
					return err
				}
			}
		case addrconfig.FileActionIoctl:
			if err := applyConfiguredGenericIoctl(fd, action); err != nil {
				return err
			}
		case addrconfig.FileActionNoAtime, addrconfig.FileActionPipeSize, addrconfig.FileActionFSFlag:
			if err := applyConfiguredLinuxPHFDAction(fd, action); err != nil {
				return err
			}
		}
	}
	noteOptionPhase("LATE")
	for _, action := range config.Actions {
		switch action.Kind {
		case addrconfig.FileActionAppend:
			if !skip.Append {
				if err := applyConfiguredAppend(fd, action); err != nil {
					return err
				}
			}
		case addrconfig.FileActionAsync:
			if !skip.Async {
				if err := applyConfiguredAsync(fd, action); err != nil {
					return err
				}
			}
		case addrconfig.FileActionTruncate:
			if err := applyConfiguredTruncate(fd, action); err != nil {
				return err
			}
		case addrconfig.FileActionSeekStart:
			if err := applyConfiguredSeek(fd, action, io.SeekStart); err != nil {
				return err
			}
		case addrconfig.FileActionSeekCurrent:
			if err := applyConfiguredSeek(fd, action, io.SeekCurrent); err != nil {
				return err
			}
		case addrconfig.FileActionSeekEnd:
			if err := applyConfiguredSeek(fd, action, io.SeekEnd); err != nil {
				return err
			}
		case addrconfig.FileActionPermLate:
			if err := applyConfiguredPerm(fd, action); err != nil {
				return err
			}
		case addrconfig.FileActionUserLate:
			if err := applyConfiguredUser(fd, action); err != nil {
				return err
			}
		case addrconfig.FileActionGroupLate:
			if err := applyConfiguredGroup(fd, action); err != nil {
				return err
			}
		case addrconfig.FileActionCloexec:
			if err := applyConfiguredCloexec(fd, action); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyConfiguredCloexec(fd int, action addrconfig.FileAction) error {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		return fmt.Errorf("cloexec: %w", err)
	}
	if action.Enabled {
		flags |= unix.FD_CLOEXEC
	} else {
		flags &^= unix.FD_CLOEXEC
	}
	noteLifecycleSyscall("F_SETFD")
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags); err != nil {
		return fmt.Errorf("cloexec: %w", err)
	}
	return nil
}

func applyConfiguredAppend(fd int, action addrconfig.FileAction) error {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return fmt.Errorf("append: %w", err)
	}
	if action.Enabled {
		flags |= unix.O_APPEND
	} else {
		flags &^= unix.O_APPEND
	}
	noteLifecycleSyscall("F_SETFL")
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags); err != nil {
		return fmt.Errorf("append: %w", err)
	}
	return nil
}

func applyConfiguredAsync(fd int, action addrconfig.FileAction) error {
	if action.Enabled && !FeatureFDAsync {
		return fmt.Errorf("%s: not supported on this platform", action.Name)
	}
	if !FeatureFDAsync {
		return nil
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return fmt.Errorf("%s: %w", action.Name, err)
	}
	if action.Enabled {
		flags |= fdAsyncFlag
	} else {
		flags &^= fdAsyncFlag
	}
	noteLifecycleSyscall("F_SETFL")
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags); err != nil {
		return fmt.Errorf("%s: %w", action.Name, err)
	}
	return nil
}

func applyConfiguredFlock(fd int, action addrconfig.FileAction) error {
	if !FeatureFlock {
		return fmt.Errorf("%s: not supported on this platform", action.Name)
	}
	how := unix.LOCK_EX
	switch action.Value {
	case 2:
		how |= unix.LOCK_NB
	case 3:
		how = unix.LOCK_SH
	case 4:
		how = unix.LOCK_SH | unix.LOCK_NB
	}
	noteLifecycleSyscall("flock")
	if err := flockFD(fd, how); err != nil {
		return fmt.Errorf("%s: %w", action.Name, err)
	}
	return nil
}

func applyConfiguredSeek(fd int, action addrconfig.FileAction, whence int) error {
	noteLifecycleSyscall("lseek")
	if _, err := unix.Seek(fd, action.Offset, whence); err != nil {
		return fmt.Errorf("%s: %w", action.Name, err)
	}
	return nil
}

func applyConfiguredTruncate(fd int, action addrconfig.FileAction) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("ftruncate: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("ftruncate: not a regular file")
	}
	noteLifecycleSyscall("ftruncate")
	if err := unix.Ftruncate(fd, action.Offset); err != nil {
		return fmt.Errorf("ftruncate: %w", err)
	}
	return nil
}

func applyConfiguredPerm(fd int, action addrconfig.FileAction) error {
	noteLifecycleSyscall("fchmod")
	if err := unix.Fchmod(fd, FileModeToUnix(UnixModeToFileMode(action.Mode))); err != nil {
		return fmt.Errorf("fchmod: %w", err)
	}
	return nil
}

func applyConfiguredUser(fd int, action addrconfig.FileAction) error {
	uid, hasUID, err := resolveUID(action.Text)
	if err != nil {
		return err
	}
	if !hasUID {
		return nil
	}
	noteLifecycleSyscall("fchown")
	if err := unix.Fchown(fd, uid, -1); err != nil {
		return fmt.Errorf("fchown: %w", err)
	}
	return nil
}

func applyConfiguredGroup(fd int, action addrconfig.FileAction) error {
	gid, hasGID, err := resolveGID(action.Text)
	if err != nil {
		return err
	}
	if !hasGID {
		return nil
	}
	noteLifecycleSyscall("fchown")
	if err := unix.Fchown(fd, -1, gid); err != nil {
		return fmt.Errorf("fchown: %w", err)
	}
	return nil
}

func applyFDLifecycleToFile(f *os.File, s parse.Spec, skip FDSkip) error {
	if f == nil || (!hasFDLifecycleOptions(s, skip) && !hasLinuxPHFDOptions(s)) {
		return nil
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		optionErr = applyFDLifecycleOnFD(int(fd), s, skip)
	})
	return errors.Join(ctrlErr, optionErr)
}

func applyFDLifecycleOnFD(fd int, s parse.Spec, skip FDSkip) error {
	if !hasFDLifecycleOptions(s, skip) && !hasLinuxPHFDOptions(s) {
		return nil
	}
	if hasFDLifecycleOptions(s, skip) && fdLifecycleTestHook != nil {
		fdLifecycleTestHook(fd)
	}
	if err := applyFDPhaseLifecycleOptions(fd, s, skip); err != nil {
		return err
	}
	if !hasFDLifecycleOptions(s, skip) {
		return nil
	}
	return applyLateLifecycle(fd, s, skip)
}

// applyFDLifecycleToStream applies descriptor lifecycle once per unique
// underlying fd in this call (FileStream R/W/C sharing one fd).
func applyFDLifecycleToStream(s parse.Spec, stream relay.Stream, skip FDSkip) error {
	return applyFDLifecycleToStreamMode(s, stream, skip, false)
}

// applyFDLifecycleLateToStream applies only late descriptor options.
// ACCEPT-FD applies after-open options before after-socket and after
// connect/accept; late follows those stages instead of after-open.
func applyFDLifecycleLateToStream(s parse.Spec, stream relay.Stream) error {
	return applyFDLifecycleToStreamMode(s, stream, FDSkip{}, true)
}

func applyFDLifecycleToStreamMode(s parse.Spec, stream relay.Stream, skip FDSkip, lateOnly bool) error {
	if lateOnly {
		if !hasFDLifecycleOptions(s, FDSkip{}) {
			return nil
		}
	} else if !hasFDLifecycleOptions(s, skip) {
		return nil
	}
	targets := streamSyscallConns(stream)
	if len(targets) == 0 {
		return fmt.Errorf("append/perm/user/group/ftruncate: stream does not expose a descriptor")
	}
	seen := make(map[int]struct{})
	for _, raw := range targets {
		var fdErr error
		ctrlErr := raw.Control(func(fd uintptr) {
			n := int(fd)
			if _, ok := seen[n]; ok {
				return
			}
			seen[n] = struct{}{}
			if lateOnly {
				fdErr = applyLateLifecycle(n, s, FDSkip{})
				return
			}
			fdErr = applyFDLifecycleOnFD(n, s, skip)
		})
		if err := errors.Join(ctrlErr, fdErr); err != nil {
			return err
		}
	}
	return nil
}

// ApplyFDLifecycleToConn applies after-open then late options on a live
// syscall.Conn (UDP/UNIX/QUIC transport, before wrapping).
func ApplyFDLifecycleToConn(c syscall.Conn, s parse.Spec) error {
	return ApplyFDLifecycleToConnSkip(c, s, FDSkip{})
}

// ApplyFDLifecycleToConnSkip applies descriptor lifecycle with opener-owned
// options skipped.
func ApplyFDLifecycleToConnSkip(c syscall.Conn, s parse.Spec, skip FDSkip) error {
	if c == nil || !hasFDLifecycleOptions(s, skip) {
		return nil
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		optionErr = applyFDLifecycleOnFD(int(fd), s, skip)
	})
	return errors.Join(ctrlErr, optionErr)
}

// ApplyFDPhaseLifecycleToConn applies only after-open owner options to a
// descriptor that is not the eventual transfer stream. Abstract UNIX stream
// listeners use this before accept; late options remain for the accepted socket.
func ApplyFDPhaseLifecycleToConn(c syscall.Conn, s parse.Spec) error {
	if c == nil {
		return nil
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		optionErr = applyFDPhaseLifecycleAll(int(fd), s)
	})
	return errors.Join(ctrlErr, optionErr)
}

// ApplyFDLifecycleToPacketConn applies descriptor lifecycle on a UDP
// PacketConn (QUIC transport) before quic-go wrapping. Rejects enabled
// options when the conn does not expose a socket.
func ApplyFDLifecycleToPacketConn(pc net.PacketConn, s parse.Spec) error {
	if pc == nil || !hasFDLifecycleOptions(s, FDSkip{}) {
		return nil
	}
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return fmt.Errorf("append/perm/user/group/ftruncate: packet connection does not expose a socket")
	}
	return ApplyFDLifecycleToConn(sc, s)
}

// ApplyFDLifecycleOnFD applies after-open then late options on a raw
// descriptor (POSIX MQ mqd, listen sockets). Caller applies once on the parent.
func ApplyFDLifecycleOnFD(fd int, s parse.Spec) error {
	return ApplyFDLifecycleOnFDSkip(fd, s, FDSkip{})
}

// ApplyFDLifecycleOnFDSkip applies descriptor lifecycle with opener-owned
// options skipped.
func ApplyFDLifecycleOnFDSkip(fd int, s parse.Spec, skip FDSkip) error {
	return applyFDLifecycleOnFD(fd, s, skip)
}

func applyFDPhaseLifecycleAll(fd int, s parse.Spec) error {
	return applyFDPhaseLifecycleOptions(fd, s, FDSkip{})
}

func applyFDPhaseLifecycleOptions(fd int, s parse.Spec, skip FDSkip) error {
	noteOptionPhase("FD")
	for _, o := range s.Options {
		name := parse.CanonicalOptionName(o.Name)
		switch name {
		case "perm":
			if skip.Perm {
				continue
			}
			if err := applyOnePerm(fd, o); err != nil {
				return err
			}
		case "user":
			if skip.User {
				continue
			}
			if err := applyOneUser(fd, o); err != nil {
				return err
			}
		case "group":
			if skip.Group {
				continue
			}
			if err := applyOneGroup(fd, o); err != nil {
				return err
			}
		case "flock":
			if err := applyOneFlock(fd, o, unix.LOCK_EX); err != nil {
				return err
			}
		case "flock-nb":
			if err := applyOneFlock(fd, o, unix.LOCK_EX|unix.LOCK_NB); err != nil {
				return err
			}
		case "flock-sh":
			if err := applyOneFlock(fd, o, unix.LOCK_SH); err != nil {
				return err
			}
		case "flock-sh-nb":
			if err := applyOneFlock(fd, o, unix.LOCK_SH|unix.LOCK_NB); err != nil {
				return err
			}
		case "ioctl-void", "ioctl-int", "ioctl-intp", "ioctl-bin", "ioctl-string":
			// Same after-open walk as perm/user/group/flock so mixed options
			// keep command-line order. Do not apply generic ioctl only in
			// applyLinuxPHFDOption (Linux-only; ioctl is Unix including Darwin).
			if err := applyGenericIoctlOption(fd, o); err != nil {
				return err
			}
		default:
			if err := applyLinuxPHFDOption(fd, o); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyLateLifecycle(fd int, s parse.Spec, skip FDSkip) error {
	noteOptionPhase("LATE")
	for _, o := range s.Options {
		switch parse.CanonicalOptionName(o.Name) {
		case "append":
			if skip.Append {
				continue
			}
			if err := applyOneAppend(fd, o); err != nil {
				return err
			}
		case "async":
			if skip.Async {
				continue
			}
			if err := applyOneAsync(fd, o); err != nil {
				return err
			}
		case "ftruncate":
			if err := applyOneFtruncate(fd, o); err != nil {
				return err
			}
		case "lseek":
			if err := applyOneLseek(fd, o, io.SeekStart); err != nil {
				return err
			}
		case "seek-cur":
			if err := applyOneLseek(fd, o, io.SeekCurrent); err != nil {
				return err
			}
		case "seek-end":
			if err := applyOneLseek(fd, o, io.SeekEnd); err != nil {
				return err
			}
		case "perm-late":
			if err := applyOnePerm(fd, o); err != nil {
				return err
			}
		case "user-late":
			if err := applyOneUser(fd, o); err != nil {
				return err
			}
		case "group-late":
			if err := applyOneGroup(fd, o); err != nil {
				return err
			}
		case "cloexec":
			if err := applyOneCloexec(fd, o); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyOneCloexec(fd int, o parse.Option) error {
	// F_GETFD, then |= or &=~ FD_CLOEXEC, then F_SETFD. Clearing Go's default
	// CLOEXEC is limited to descriptors owned by ApplyFDOptions /
	// SetupStream / ApplyFDLifecycleToConn. Streams with no fd reject.
	enable := o.Active()
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		return fmt.Errorf("cloexec: %w", err)
	}
	if enable {
		flags |= unix.FD_CLOEXEC
	} else {
		flags &^= unix.FD_CLOEXEC
	}
	noteLifecycleSyscall("F_SETFD")
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags); err != nil {
		return fmt.Errorf("cloexec: %w", err)
	}
	return nil
}

func applyOneAppend(fd int, o parse.Option) error {
	enable := o.Active()
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return fmt.Errorf("append: %w", err)
	}
	if enable {
		flags |= unix.O_APPEND
	} else {
		flags &^= unix.O_APPEND
	}
	noteLifecycleSyscall("F_SETFL")
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags); err != nil {
		return fmt.Errorf("append: %w", err)
	}
	return nil
}

func applyOneAsync(fd int, o parse.Option) error {
	enable := o.Active()
	if enable && !FeatureFDAsync {
		return fmt.Errorf("%s: not supported on this platform", o.OriginalSpelling())
	}
	if !FeatureFDAsync {
		return nil
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return fmt.Errorf("%s: %w", o.OriginalSpelling(), err)
	}
	if enable {
		flags |= fdAsyncFlag
	} else {
		flags &^= fdAsyncFlag
	}
	noteLifecycleSyscall("F_SETFL")
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags); err != nil {
		return fmt.Errorf("%s: %w", o.OriginalSpelling(), err)
	}
	return nil
}

func applyOneFlock(fd int, o parse.Option, how int) error {
	if !o.Active() {
		return nil
	}
	if !FeatureFlock {
		return fmt.Errorf("%s: not supported on this platform", o.OriginalSpelling())
	}
	noteLifecycleSyscall("flock")
	if err := flockFD(fd, how); err != nil {
		return fmt.Errorf("%s: %w", o.OriginalSpelling(), err)
	}
	return nil
}

func applyOneLseek(fd int, o parse.Option, whence int) error {
	off, err := parseLseekOffset(o)
	if err != nil {
		return err
	}
	noteLifecycleSyscall("lseek")
	if _, err := unix.Seek(fd, off, whence); err != nil {
		return fmt.Errorf("%s: %w", o.OriginalSpelling(), err)
	}
	return nil
}

func applyOneFtruncate(fd int, o parse.Option) error {
	n, err := parseFtruncateOption(o)
	if err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("ftruncate: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("ftruncate: not a regular file")
	}
	noteLifecycleSyscall("ftruncate")
	if err := unix.Ftruncate(fd, n); err != nil {
		return fmt.Errorf("ftruncate: %w", err)
	}
	return nil
}

func applyOnePerm(fd int, o parse.Option) error {
	if !o.Has {
		return nil
	}
	mode, err := parseModeT(o.OriginalSpelling(), o.Value)
	if err != nil {
		return err
	}
	noteLifecycleSyscall("fchmod")
	if err := unix.Fchmod(fd, FileModeToUnix(mode)); err != nil {
		return fmt.Errorf("fchmod: %w", err)
	}
	return nil
}

func applyOneUser(fd int, o parse.Option) error {
	v, err := requiredLifecycleOptionValue(o)
	if err != nil {
		return err
	}
	uid, hasU, err := resolveUID(v)
	if err != nil {
		return err
	}
	if !hasU {
		return nil
	}
	noteLifecycleSyscall("fchown")
	if err := unix.Fchown(fd, uid, -1); err != nil {
		return fmt.Errorf("fchown: %w", err)
	}
	return nil
}

func applyOneGroup(fd int, o parse.Option) error {
	v, err := requiredLifecycleOptionValue(o)
	if err != nil {
		return err
	}
	gid, hasG, err := resolveGID(v)
	if err != nil {
		return err
	}
	if !hasG {
		return nil
	}
	noteLifecycleSyscall("fchown")
	if err := unix.Fchown(fd, -1, gid); err != nil {
		return fmt.Errorf("fchown: %w", err)
	}
	return nil
}
