//go:build linux

package xio

import (
	"os"

	"golang.org/x/sys/unix"
)

// pinUnlinkPath holds path's inode without opening it for I/O. O_PATH is not a
// FIFO reader, so a later blocking open(O_RDONLY) still waits for a writer.
func pinUnlinkPath(path string) *os.File {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0) // #nosec G304 -- endpoint path we created and are about to unregister on signal
	if err != nil {
		return nil
	}
	return os.NewFile(uintptr(fd), path)
}
