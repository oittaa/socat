//go:build windows

package xio

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

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
	if !hasFDLifecycleOptions(s) {
		return nil
	}
	seen := make(map[uintptr]struct{})
	for _, t := range streamSyscallConnTargets(stream) {
		if isFDLifecycleApplied(t.file) {
			continue
		}
		var fdErr error
		ctrlErr := t.raw.Control(func(fd uintptr) {
			if _, ok := seen[fd]; ok {
				return
			}
			seen[fd] = struct{}{}
			fdErr = applyFDLifecycleOnHandle(fd, s)
		})
		if err := errors.Join(ctrlErr, fdErr); err != nil {
			return err
		}
	}
	return nil
}

func applyFDLifecycleOnHandle(fd uintptr, s parse.Spec) error {
	if err := applyWindowsFDPhase(s); err != nil {
		return err
	}
	return applyWindowsLate(fd, s)
}

func applyWindowsFDPhase(s parse.Spec) error {
	skipOwner := skipDescriptorOwnerOpts(s.Type)
	for _, o := range s.Options {
		switch parse.CanonicalOptionName(o.Name) {
		case "perm":
			if skipOwner {
				continue
			}
			return fmt.Errorf("perm: fchmod is not supported on windows")
		case "user":
			if skipOwner {
				continue
			}
			return fmt.Errorf("user: not supported on windows")
		case "group":
			if skipOwner {
				continue
			}
			return fmt.Errorf("group: not supported on windows")
		}
	}
	return nil
}

func applyWindowsLate(fd uintptr, s parse.Spec) error {
	skipTrunc := skipNamedFileFtruncate(s.Type)
	for _, o := range s.Options {
		switch parse.CanonicalOptionName(o.Name) {
		case "append":
			if err := applyWindowsOneAppend(s); err != nil {
				return err
			}
		case "ftruncate":
			if skipTrunc {
				continue
			}
			if err := applyWindowsOneFtruncate(fd, o); err != nil {
				return err
			}
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
