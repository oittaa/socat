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
	return errors.Join(ctrlErr, optionErr)
}

func applyFDLifecycleToStream(s parse.Spec, stream relay.Stream) error {
	if !hasFDLifecycleOptions(s) {
		return nil
	}
	seen := make(map[uintptr]struct{})
	for _, raw := range streamSyscallConns(stream) {
		var fdErr error
		ctrlErr := raw.Control(func(fd uintptr) {
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
	if err := applyWindowsOwner(s); err != nil {
		return err
	}
	if err := applyWindowsPerm(s); err != nil {
		return err
	}
	if err := applyWindowsAppend(s); err != nil {
		return err
	}
	return applyWindowsFtruncate(fd, s)
}

func applyWindowsOwner(s parse.Spec) error {
	if skipDescriptorOwnerOpts(s.Type) {
		return nil
	}
	if _, ok := lastLifecycleOption(s, "user", "uid", "owner"); ok {
		return fmt.Errorf("user: not supported on windows")
	}
	if _, ok := lastLifecycleOption(s, "group", "gid"); ok {
		return fmt.Errorf("group: not supported on windows")
	}
	return nil
}

func applyWindowsPerm(s parse.Spec) error {
	if skipDescriptorOwnerOpts(s.Type) {
		return nil
	}
	if _, ok := lastLifecycleOption(s, "perm", "mode"); ok {
		return fmt.Errorf("perm: fchmod is not supported on windows")
	}
	return nil
}

func applyWindowsAppend(s parse.Spec) error {
	_, present := optionBoolAny(s, "append")
	if !present {
		return nil
	}
	switch strings.ToUpper(s.Type) {
	case "OPEN", "FILE", "CREATE", "CREAT", "GOPEN":
		return nil
	default:
		return fmt.Errorf("append: fcntl O_APPEND is not supported on windows")
	}
}

func applyWindowsFtruncate(fd uintptr, s parse.Spec) error {
	if skipNamedFileFtruncate(s.Type) {
		return nil
	}
	n, present, err := parseFtruncateLength(s)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	h := windows.Handle(fd)
	cur, err := windows.Seek(h, 0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("ftruncate: not a regular file: %w", err)
	}
	if _, err := windows.Seek(h, n, io.SeekStart); err != nil {
		return fmt.Errorf("ftruncate: %w", err)
	}
	if err := windows.SetEndOfFile(h); err != nil {
		_, _ = windows.Seek(h, cur, io.SeekStart)
		return fmt.Errorf("ftruncate: not a regular file: %w", err)
	}
	if _, err := windows.Seek(h, cur, io.SeekStart); err != nil {
		return fmt.Errorf("ftruncate: %w", err)
	}
	return nil
}
