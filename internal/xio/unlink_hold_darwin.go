//go:build darwin

package xio

import (
	"os"

	"golang.org/x/sys/unix"
)

// pinUnlinkPath holds path's inode without opening it for I/O. O_EVTONLY is
// Darwin's event-only descriptor (no FIFO reader), matching Linux O_PATH.
func pinUnlinkPath(path string) *os.File {
	fd, err := unix.Open(path, unix.O_EVTONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0) // #nosec G304 -- endpoint path we created and are about to unregister on signal
	if err != nil {
		return nil
	}
	return os.NewFile(uintptr(fd), path)
}
