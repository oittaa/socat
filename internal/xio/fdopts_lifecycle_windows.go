//go:build windows

package xio

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/windows"
)

func applyFDLifecycleToFile(f *os.File, s parse.Spec) error {
	if f == nil || !hasFDLifecycleOptions(s) {
		return nil
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		optionErr = applyFDLifecycleOnHandle(fd, s)
	})
	if err := errors.Join(ctrlErr, optionErr); err != nil {
		return err
	}
	markFDLifecycleApplied(f)
	return nil
}

func applyFDLifecycleToStream(s parse.Spec, stream relay.Stream) error {
	return applyFDLifecycleToStreamMode(s, stream, false)
}

func applyFDLifecycleLateToStream(s parse.Spec, stream relay.Stream) error {
	return applyFDLifecycleToStreamMode(s, stream, true)
}

func applyFDLifecycleToStreamMode(s parse.Spec, stream relay.Stream, lateOnly bool) error {
	if !hasFDLifecycleOptions(s) {
		return nil
	}
	if wrapHidesDescriptor(s) {
		return nil
	}
	targets := streamSyscallConnTargets(stream)
	if len(targets) == 0 {
		return fmt.Errorf("append/perm/user/group/ftruncate: stream does not expose a descriptor")
	}
	seen := make(map[uintptr]struct{})
	for _, t := range targets {
		if isFDLifecycleApplied(t.file) || isConnLifecycleApplied(t.conn) {
			continue
		}
		var fdErr error
		ctrlErr := t.raw.Control(func(fd uintptr) {
			if _, ok := seen[fd]; ok {
				return
			}
			seen[fd] = struct{}{}
			if lateOnly {
				fdErr = applyWindowsLate(fd, s)
				return
			}
			fdErr = applyFDLifecycleOnHandle(fd, s)
		})
		if err := errors.Join(ctrlErr, fdErr); err != nil {
			return err
		}
		markFDLifecycleApplied(t.file)
		markConnLifecycleApplied(t.conn)
	}
	return nil
}

// ApplyFDLifecycleToConn applies PH_OPEN, PH_FD, then PH_LATE on a live
// syscall.Conn.
func ApplyFDLifecycleToConn(c syscall.Conn, s parse.Spec) error {
	if c == nil || !hasFDLifecycleOptions(s) {
		return nil
	}
	if isConnLifecycleApplied(c) {
		return nil
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		optionErr = applyFDLifecycleOnHandle(fd, s)
	})
	if err := errors.Join(ctrlErr, optionErr); err != nil {
		return err
	}
	markConnLifecycleApplied(c)
	return nil
}

// ApplyFDPhaseLifecycleToConn applies only PH_FD owner options.
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
		optionErr = applyWindowsFDPhaseOptions(s, false)
	})
	return errors.Join(ctrlErr, optionErr)
}

// ApplyFDLifecycleToPacketConn applies descriptor lifecycle on a PacketConn.
func ApplyFDLifecycleToPacketConn(pc net.PacketConn, s parse.Spec) error {
	if pc == nil || !hasFDLifecycleOptions(s) {
		return nil
	}
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return fmt.Errorf("append/perm/user/group/ftruncate: packet connection does not expose a socket")
	}
	return ApplyFDLifecycleToConn(sc, s)
}

// ApplyFDLifecycleOnFD applies PH_OPEN, PH_FD, then PH_LATE on a raw handle.
func ApplyFDLifecycleOnFD(fd int, s parse.Spec) error {
	return applyFDLifecycleOnHandle(uintptr(fd), s)
}

func applyFDLifecycleOnHandle(fd uintptr, s parse.Spec) error {
	if err := applyWindowsOpen(fd, s); err != nil {
		return err
	}
	if err := applyWindowsFDPhase(s); err != nil {
		return err
	}
	return applyWindowsLate(fd, s)
}

// applyWindowsOpen implements classic's PH_OPEN O_NOINHERIT option on the
// native Win32 handle. Go does not use Cygwin's fcntl/open flag layer, so the
// equivalent operation is HANDLE_FLAG_INHERIT itself.
func applyWindowsOpen(fd uintptr, s parse.Spec) error {
	noteOptionPhase("OPEN")
	for _, o := range s.Options {
		if parse.CanonicalOptionName(o.Name) != "noinherit" {
			continue
		}
		flags := uint32(0)
		if !optionEnabled(o) {
			flags = windows.HANDLE_FLAG_INHERIT
		}
		noteLifecycleSyscall("SetHandleInformation")
		if err := windows.SetHandleInformation(windows.Handle(fd), windows.HANDLE_FLAG_INHERIT, flags); err != nil {
			return fmt.Errorf("%s: SetHandleInformation: %w", o.OriginalSpelling(), err)
		}
	}
	return nil
}

func applyWindowsFDPhase(s parse.Spec) error {
	return applyWindowsFDPhaseOptions(s, true)
}

func applyWindowsFDPhaseOptions(s parse.Spec, honorTargetSkip bool) error {
	noteOptionPhase("FD")
	for _, o := range s.Options {
		name := parse.CanonicalOptionName(o.Name)
		switch name {
		case "perm":
			if honorTargetSkip && skipDescriptorOwnerOption(s, name) {
				continue
			}
			return fmt.Errorf("perm: fchmod is not supported on windows")
		case "user":
			if honorTargetSkip && skipDescriptorOwnerOption(s, name) {
				continue
			}
			return fmt.Errorf("user: not supported on windows")
		case "group":
			if honorTargetSkip && skipDescriptorOwnerOption(s, name) {
				continue
			}
			return fmt.Errorf("group: not supported on windows")
		case "flock", "flock-nb", "flock-sh", "flock-sh-nb":
			if !optionEnabled(o) {
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

func applyWindowsLate(fd uintptr, s parse.Spec) error {
	noteOptionPhase("LATE")
	skipAppend := skipNamedFileAppend(s.Type)
	skipAsync := skipNamedFileAsync(s.Type)
	for _, o := range s.Options {
		switch parse.CanonicalOptionName(o.Name) {
		case "append":
			if skipAppend {
				continue
			}
			if err := applyWindowsOneAppend(s); err != nil {
				return err
			}
		case "async":
			if skipAsync {
				continue
			}
			if !optionEnabled(o) {
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

func applyWindowsOneAppend(s parse.Spec) error {
	switch strings.ToUpper(s.Type) {
	case "OPEN", "FILE", "CREATE", "CREAT", "GOPEN":
		return nil
	default:
		return fmt.Errorf("append: fcntl O_APPEND is not supported on windows")
	}
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
