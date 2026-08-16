//go:build linux

package fileopen

import (
	"os"

	"golang.org/x/sys/unix"
)

func pipeBufSize(pw *os.File) int {
	if n, err := unix.FcntlInt(pw.Fd(), unix.F_GETPIPE_SZ, 0); err == nil && n > 0 {
		return n
	}
	return 65536
}
