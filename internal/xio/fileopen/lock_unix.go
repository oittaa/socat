//go:build linux || darwin

package fileopen

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func lockFile(file *os.File, write, wait bool) error {
	lockType := int16(unix.F_RDLCK)
	if write {
		lockType = unix.F_WRLCK
	}
	command := unix.F_SETLK
	if wait {
		command = unix.F_SETLKW
	}
	return unix.FcntlFlock(file.Fd(), command, &unix.Flock_t{
		Type:   lockType,
		Whence: int16(io.SeekStart),
		Start:  0,
		Len:    0,
	})
}
