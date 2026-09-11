//go:build windows

package xio

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/windows"
)

func applyFDLifecycleToFile(f *os.File, s parse.Spec, skip FDSkip) error {
	if f == nil || !hasFDLifecycleOptions(s, skip) {
		return nil
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		optionErr = applyFDLifecycleOnHandle(fd, s, skip)
	})
	return errors.Join(ctrlErr, optionErr)
}

func applyFDLifecycleToStream(s parse.Spec, stream relay.Stream, skip FDSkip) error {
	return applyFDLifecycleToStreamMode(s, stream, skip, false)
}

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
	seen := make(map[uintptr]struct{})
	for _, raw := range targets {
		var fdErr error
		ctrlErr := raw.Control(func(fd uintptr) {
			if _, ok := seen[fd]; ok {
				return
			}
			seen[fd] = struct{}{}
			if lateOnly {
				fdErr = applyWindowsLate(fd, s, FDSkip{})
				return
			}
			fdErr = applyFDLifecycleOnHandle(fd, s, skip)
		})
		if err := errors.Join(ctrlErr, fdErr); err != nil {
			return err
		}
	}
	return nil
}

// ApplyFDLifecycleToConn applies after-open, after-fd, then late options
// on a live syscall.Conn.
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
		optionErr = applyFDLifecycleOnHandle(fd, s, skip)
	})
	return errors.Join(ctrlErr, optionErr)
}

// ApplyFDPhaseLifecycleToConn applies after-fd owner options.
func ApplyFDPhaseLifecycleToConn(c syscall.Conn, s parse.Spec) error {
	if c == nil {
		return nil
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	ctrlErr := raw.Control(func(_ uintptr) {
		optionErr = applyWindowsFDPhaseOptions(s, FDSkip{})
	})
	return errors.Join(ctrlErr, optionErr)
}

// ApplyFDLifecycleToPacketConn applies descriptor lifecycle on a PacketConn.
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

// ApplyFDLifecycleOnFD applies after-open, after-fd, then late options on
// a raw handle.
func ApplyFDLifecycleOnFD(fd int, s parse.Spec) error {
	return ApplyFDLifecycleOnFDSkip(fd, s, FDSkip{})
}

func ApplyFDLifecycleOnFDSkip(fd int, s parse.Spec, skip FDSkip) error {
	return applyFDLifecycleOnHandle(uintptr(fd), s, skip)
}

func applyFDLifecycleOnHandle(fd uintptr, s parse.Spec, skip FDSkip) error {
	if err := applyWindowsOpen(fd, s); err != nil {
		return err
	}
	if err := applyWindowsFDPhaseOptions(s, skip); err != nil {
		return err
	}
	return applyWindowsLate(fd, s, skip)
}

// applyWindowsOpen applies noinherit on the native Win32 handle via
// HANDLE_FLAG_INHERIT.
func applyWindowsOpen(fd uintptr, s parse.Spec) error {
	noteOptionPhase("OPEN")
	for _, o := range s.Options {
		if parse.CanonicalOptionName(o.Name) != "noinherit" {
			continue
		}
		flags := uint32(0)
		if !o.Active() {
			flags = windows.HANDLE_FLAG_INHERIT
		}
		noteLifecycleSyscall("SetHandleInformation")
		if err := windows.SetHandleInformation(windows.Handle(fd), windows.HANDLE_FLAG_INHERIT, flags); err != nil {
			return fmt.Errorf("%s: SetHandleInformation: %w", o.OriginalSpelling(), err)
		}
	}
	return nil
}

func applyWindowsFDPhaseOptions(s parse.Spec, skip FDSkip) error {
	noteOptionPhase("FD")
	for _, o := range s.Options {
		name := parse.CanonicalOptionName(o.Name)
		switch name {
		case "perm":
			if skip.Perm {
				continue
			}
			return fmt.Errorf("perm: fchmod is not supported on windows")
		case "user":
			if skip.User {
				continue
			}
			return fmt.Errorf("user: not supported on windows")
		case "group":
			if skip.Group {
				continue
			}
			return fmt.Errorf("group: not supported on windows")
		case "flock", "flock-nb", "flock-sh", "flock-sh-nb":
			if !o.Active() {
				continue
			}
			return fmt.Errorf("%s: flock is not supported on windows", o.OriginalSpelling())
		case "ioctl-void", "ioctl-int", "ioctl-intp", "ioctl-bin", "ioctl-string":
			if err := applyGenericIoctlOption(0, o); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyWindowsLate(fd uintptr, s parse.Spec, skip FDSkip) error {
	noteOptionPhase("LATE")
	for _, o := range s.Options {
		switch parse.CanonicalOptionName(o.Name) {
		case "append":
			if skip.Append {
				continue
			}
			if err := applyWindowsOneAppend(); err != nil {
				return err
			}
		case "async":
			if skip.Async {
				continue
			}
			if !o.Active() {
				continue
			}
			return fmt.Errorf("%s: fcntl O_ASYNC is not supported on windows", o.OriginalSpelling())
		case "ftruncate":
			if err := applyWindowsOneFtruncate(fd, o); err != nil {
				return err
			}
		case "lseek":
			if err := applyWindowsOneLseek(fd, o, io.SeekStart); err != nil {
				return err
			}
		case "seek-cur":
			if err := applyWindowsOneLseek(fd, o, io.SeekCurrent); err != nil {
				return err
			}
		case "seek-end":
			if err := applyWindowsOneLseek(fd, o, io.SeekEnd); err != nil {
				return err
			}
		case "perm-late":
			return fmt.Errorf("perm-late: fchmod is not supported on windows")
		case "user-late":
			return fmt.Errorf("user-late: not supported on windows")
		case "group-late":
			return fmt.Errorf("group-late: not supported on windows")
		case "cloexec":
			return fmt.Errorf("%s: fcntl F_SETFD is not supported on windows", o.OriginalSpelling())
		}
	}
	return nil
}

func applyWindowsOneAppend() error {
	return fmt.Errorf("append: fcntl O_APPEND is not supported on windows")
}

func applyWindowsOneFtruncate(fd uintptr, o parse.Option) error {
	n, err := parseFtruncateOption(o)
	if err != nil {
		return err
	}
	h := windows.Handle(fd)
	cur, err := windows.Seek(h, 0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("ftruncate: not a regular file: %w", err)
	}
	if _, err := windows.Seek(h, n, io.SeekStart); err != nil {
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

func applyWindowsOneLseek(fd uintptr, o parse.Option, whence int) error {
	off, err := parseLseekOffset(o)
	if err != nil {
		return err
	}
	noteLifecycleSyscall("lseek")
	if _, err := windows.Seek(windows.Handle(fd), off, whence); err != nil {
		return fmt.Errorf("%s: %w", o.OriginalSpelling(), err)
	}
	return nil
}
