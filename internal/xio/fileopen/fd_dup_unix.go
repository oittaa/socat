//go:build linux || darwin

package fileopen

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func duplicateInheritedFD(fd int) (int, error) {
	return unix.Dup(fd)
}

func closeInheritedFD(fd int) error {
	return unix.Close(fd)
}

func mirrorInheritedCloexec(orig int, session *os.File) error {
	flags, err := unix.FcntlInt(session.Fd(), unix.F_GETFD, 0)
	if err != nil {
		return fmt.Errorf("cloexec: %w", err)
	}
	if _, err := unix.FcntlInt(uintptr(orig), unix.F_SETFD, flags); err != nil {
		return fmt.Errorf("cloexec: %w", err)
	}
	return nil
}
