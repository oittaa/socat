//go:build linux

package fileopen

import (
	"os"

	"golang.org/x/sys/unix"
)

// pipeBufSize queries the pipe capacity. File.Fd would switch the pipe to
// blocking mode and disable later write deadlines.
func pipeBufSize(pw *os.File) int {
	raw, err := pw.SyscallConn()
	if err != nil {
		return 65536
	}
	n := 0
	_ = raw.Control(func(fd uintptr) {
		if sz, fcntlErr := unix.FcntlInt(fd, unix.F_GETPIPE_SZ, 0); fcntlErr == nil && sz > 0 {
			n = sz
		}
	})
	if n > 0 {
		return n
	}
	return 65536
}
