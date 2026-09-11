//go:build windows

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
	"golang.org/x/sys/windows"
)

// ApplyConfiguredFDOptions applies the supported prepared descriptor actions
// on a Windows handle. Unsupported Unix-only actions retain their established
// rejection when they reach their resource owner.
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
		actionErr = applyConfiguredWindowsFD(fd, config, skip)
	})
	return errors.Join(controlErr, actionErr)
}

func applyConfiguredWindowsFD(fd uintptr, config addrconfig.File, skip FDSkip) error {
	if err := applyConfiguredWindowsOpen(fd, config); err != nil {
		return err
	}
	if err := applyConfiguredWindowsFDPhase(config, skip); err != nil {
		return err
	}
	return applyConfiguredWindowsLate(fd, config, skip)
}

func applyConfiguredWindowsOpen(fd uintptr, config addrconfig.File) error {
	noteOptionPhase("OPEN")
	for _, action := range config.Actions {
		if action.Kind != addrconfig.FileActionNoInherit {
			continue
		}
		flags := uint32(0)
		if !action.Enabled {
			flags = windows.HANDLE_FLAG_INHERIT
		}
		noteLifecycleSyscall("SetHandleInformation")
		if err := windows.SetHandleInformation(windows.Handle(fd), windows.HANDLE_FLAG_INHERIT, flags); err != nil {
			return fmt.Errorf("%s: SetHandleInformation: %w", action.Name, err)
		}
	}
	return nil
}

func applyConfiguredWindowsFDPhase(config addrconfig.File, skip FDSkip) error {
	noteOptionPhase("FD")
	for _, action := range config.Actions {
		switch action.Kind {
		case addrconfig.FileActionPerm:
			if !skip.Perm {
				return fmt.Errorf("perm: fchmod is not supported on windows")
			}
		case addrconfig.FileActionUser:
			if !skip.User {
				return fmt.Errorf("user: not supported on windows")
			}
		case addrconfig.FileActionGroup:
			if !skip.Group {
				return fmt.Errorf("group: not supported on windows")
			}
		case addrconfig.FileActionFlock:
			if action.Enabled {
				return fmt.Errorf("%s: flock is not supported on windows", action.Name)
			}
		case addrconfig.FileActionIoctl:
			if err := applyConfiguredGenericIoctl(0, action); err != nil {
				return err
			}
		case addrconfig.FileActionNoAtime:
			if action.Enabled {
				return fmt.Errorf("o-noatime: not supported on this platform")
			}
		case addrconfig.FileActionPipeSize:
			return fmt.Errorf("f-setpipe-sz: not supported on this platform")
		case addrconfig.FileActionFSFlag:
			if action.Enabled {
				return fmt.Errorf("%s: not supported on this platform", action.Name)
			}
		}
	}
	return nil
}

func applyConfiguredWindowsLate(fd uintptr, config addrconfig.File, skip FDSkip) error {
	noteOptionPhase("LATE")
	for _, action := range config.Actions {
		switch action.Kind {
		case addrconfig.FileActionAppend:
			if !skip.Append {
				return fmt.Errorf("append: fcntl O_APPEND is not supported on windows")
			}
		case addrconfig.FileActionAsync:
			if !skip.Async && action.Enabled {
				return fmt.Errorf("async: fcntl O_ASYNC is not supported on windows")
			}
		case addrconfig.FileActionTruncate:
			if err := configuredWindowsTruncate(fd, action.Offset); err != nil {
				return err
			}
		case addrconfig.FileActionSeekStart:
			if err := configuredWindowsSeek(fd, action.Offset, io.SeekStart, action.Name); err != nil {
				return err
			}
		case addrconfig.FileActionSeekCurrent:
			if err := configuredWindowsSeek(fd, action.Offset, io.SeekCurrent, action.Name); err != nil {
				return err
			}
		case addrconfig.FileActionSeekEnd:
			if err := configuredWindowsSeek(fd, action.Offset, io.SeekEnd, action.Name); err != nil {
				return err
			}
		case addrconfig.FileActionPermLate:
			return fmt.Errorf("perm-late: fchmod is not supported on windows")
		case addrconfig.FileActionUserLate:
			return fmt.Errorf("user-late: not supported on windows")
		case addrconfig.FileActionGroupLate:
			return fmt.Errorf("group-late: not supported on windows")
		case addrconfig.FileActionCloexec:
			return fmt.Errorf("%s: fcntl F_SETFD is not supported on windows", action.Name)
		}
	}
	return nil
}

func configuredWindowsTruncate(fd uintptr, offset int64) error {
	h := windows.Handle(fd)
	cur, err := windows.Seek(h, 0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("ftruncate: not a regular file: %w", err)
	}
	if _, err := windows.Seek(h, offset, io.SeekStart); err != nil {
		return fmt.Errorf("ftruncate: %w", err)
	}
	noteLifecycleSyscall("ftruncate")
	if err := windows.SetEndOfFile(h); err != nil {
		_, _ = windows.Seek(h, cur, io.SeekStart)
		return fmt.Errorf("ftruncate: not a regular file: %w", err)
	}
	if _, err := windows.Seek(h, cur, io.SeekStart); err != nil {
		return fmt.Errorf("ftruncate: %w", err)
	}
	return nil
}

func configuredWindowsSeek(fd uintptr, offset int64, whence int, name string) error {
	noteLifecycleSyscall("lseek")
	if _, err := windows.Seek(windows.Handle(fd), offset, whence); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func applyFDLifecycleToFile(f *os.File, s addrconfig.Address, skip FDSkip) error {
	config := s
	return ApplyConfiguredFDOptions(f, config.File, skip)
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
	seen := make(map[uintptr]struct{})
	for _, raw := range targets {
		var fdErr error
		ctrlErr := raw.Control(func(fd uintptr) {
			if _, ok := seen[fd]; ok {
				return
			}
			seen[fd] = struct{}{}
			if lateOnly {
				fdErr = applyConfiguredWindowsLate(fd, config.File, FDSkip{})
				return
			}
			fdErr = applyConfiguredWindowsFD(fd, config.File, skip)
		})
		if err := errors.Join(ctrlErr, fdErr); err != nil {
			return err
		}
	}
	return nil
}

// ApplyFDLifecycleToConn applies after-open, after-fd, then late options
// on a live syscall.Conn.
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
		optionErr = applyConfiguredWindowsFD(fd, config.File, skip)
	})
	return errors.Join(ctrlErr, optionErr)
}

// ApplyFDPhaseLifecycleToConn applies after-fd owner options.
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
	ctrlErr := raw.Control(func(_ uintptr) {
		optionErr = applyConfiguredWindowsFDPhase(config.File, FDSkip{})
	})
	return errors.Join(ctrlErr, optionErr)
}

// ApplyFDLifecycleToPacketConn applies descriptor lifecycle on a PacketConn.
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

// ApplyFDLifecycleOnFD applies after-open, after-fd, then late options on
// a raw handle.
func ApplyFDLifecycleOnFD(fd int, s addrconfig.Address) error {
	return ApplyFDLifecycleOnFDSkip(fd, s, FDSkip{})
}

func ApplyFDLifecycleOnFDSkip(fd int, s addrconfig.Address, skip FDSkip) error {
	config := s
	return applyConfiguredWindowsFD(uintptr(fd), config.File, skip)
}
