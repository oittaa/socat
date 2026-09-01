//go:build linux || darwin

package fileopen

import (
	"fmt"
	"os"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func duplicateInheritedFD(fd int) (int, error) {
	n, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	return n, nil
}

func closeInheritedFD(fd int) error {
	return unix.Close(fd)
}

func mirrorInheritedFDFlags(orig int, session *os.File, _ parse.Spec) error {
	flags, err := unix.FcntlInt(session.Fd(), unix.F_GETFD, 0)
	if err != nil {
		return fmt.Errorf("cloexec: %w", err)
	}
	if _, err := unix.FcntlInt(uintptr(orig), unix.F_SETFD, flags); err != nil {
		return fmt.Errorf("cloexec: %w", err)
	}
	return nil
}
