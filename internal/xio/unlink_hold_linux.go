//go:build linux

package xio

import (
	"os"

	"golang.org/x/sys/unix"
)

// holdUnlinkIdentity pins path's inode without opening it for I/O. O_PATH is
// not a FIFO reader, so a later blocking open(O_RDONLY) still waits for a writer.
func holdUnlinkIdentity(path string) (*os.File, os.FileInfo, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0) // #nosec G304 -- endpoint path we created and are about to unregister on signal
	if err != nil {
		info, e := os.Lstat(path)
		return nil, info, e
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, info, nil
}
