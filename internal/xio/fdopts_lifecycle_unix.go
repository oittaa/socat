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

func applyConfiguredFDOnFD(fd int, config addrconfig.File, skip FDSkip) error {
	if !hasConfiguredFDActions(config, skip) {
		return nil
	}
	if fdLifecycleTestHook != nil {
		fdLifecycleTestHook(fd)
	}
	if err := applyConfiguredFDPhase(fd, config, skip); err != nil {
		return err
	}
	return applyConfiguredLate(fd, config, skip)
}

func applyConfiguredFDPhase(fd int, config addrconfig.File, skip FDSkip) error {
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
	return nil
}

func applyConfiguredLate(fd int, config addrconfig.File, skip FDSkip) error {
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

func applyFDLifecycleToFile(f *os.File, s addrconfig.Address, skip FDSkip) error {
	config := s
	return ApplyConfiguredFDOptions(f, config.File, skip)
}

func applyFDLifecycleOnFD(fd int, s addrconfig.Address, skip FDSkip) error {
	config := s
	return applyConfiguredFDOnFD(fd, config.File, skip)
}

// applyFDLifecycleToStream applies descriptor lifecycle once per unique
// underlying fd in this call (FileStream R/W/C sharing one fd).
func applyFDLifecycleToStream(s addrconfig.Address, stream relay.Stream, skip FDSkip) error {
	return applyFDLifecycleToStreamMode(s, stream, skip, false)
}

// applyFDLifecycleLateToStream applies only late descriptor options.
// ACCEPT-FD applies after-open options before after-socket and after
// connect/accept; late follows those stages instead of after-open.
func applyFDLifecycleLateToStream(s addrconfig.Address, stream relay.Stream) error {
	return applyFDLifecycleToStreamMode(s, stream, FDSkip{}, true)
}

func applyFDLifecycleToStreamMode(s addrconfig.Address, stream relay.Stream, skip FDSkip, lateOnly bool) error {
	config := s
	if lateOnly {
		if !hasConfiguredFDActions(config.File, FDSkip{}) {
			return nil
		}
	} else if !hasConfiguredFDActions(config.File, skip) {
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
				fdErr = applyConfiguredLate(n, config.File, FDSkip{})
				return
			}
			fdErr = applyConfiguredFDOnFD(n, config.File, skip)
		})
		if err := errors.Join(ctrlErr, fdErr); err != nil {
			return err
		}
	}
	return nil
}

// ApplyFDLifecycleToConn applies after-open then late options on a live
// syscall.Conn (UDP/UNIX/QUIC transport, before wrapping).
func ApplyFDLifecycleToConn(c syscall.Conn, s addrconfig.Address) error {
	return ApplyFDLifecycleToConnSkip(c, s, FDSkip{})
}

// ApplyFDLifecycleToConnSkip applies descriptor lifecycle with opener-owned
// options skipped.
func ApplyFDLifecycleToConnSkip(c syscall.Conn, s addrconfig.Address, skip FDSkip) error {
	if c == nil {
		return nil
	}
	config := s
	if !hasConfiguredFDActions(config.File, skip) {
		return nil
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		optionErr = applyConfiguredFDOnFD(int(fd), config.File, skip)
	})
	return errors.Join(ctrlErr, optionErr)
}

// ApplyFDPhaseLifecycleToConn applies only after-open owner options to a
// descriptor that is not the eventual transfer stream. Abstract UNIX stream
// listeners use this before accept; late options remain for the accepted socket.
func ApplyFDPhaseLifecycleToConn(c syscall.Conn, s addrconfig.Address) error {
	if c == nil {
		return nil
	}
	config := s
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		optionErr = applyConfiguredFDPhase(int(fd), config.File, FDSkip{})
	})
	return errors.Join(ctrlErr, optionErr)
}

// ApplyFDLifecycleToPacketConn applies descriptor lifecycle on a UDP
// PacketConn (QUIC transport) before quic-go wrapping. Rejects enabled
// options when the conn does not expose a socket.
func ApplyFDLifecycleToPacketConn(pc net.PacketConn, s addrconfig.Address) error {
	if pc == nil {
		return nil
	}
	config := s
	if !hasConfiguredFDActions(config.File, FDSkip{}) {
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
func ApplyFDLifecycleOnFD(fd int, s addrconfig.Address) error {
	return ApplyFDLifecycleOnFDSkip(fd, s, FDSkip{})
}

// ApplyFDLifecycleOnFDSkip applies descriptor lifecycle with opener-owned
// options skipped.
func ApplyFDLifecycleOnFDSkip(fd int, s addrconfig.Address, skip FDSkip) error {
	return applyFDLifecycleOnFD(fd, s, skip)
}
