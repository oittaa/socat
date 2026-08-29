//go:build linux || darwin

package fileopen

import (
	"os"

	"golang.org/x/sys/unix"
)

// fillPipe writes zeros until the pipe buffer is full (STALL write side).
func fillPipe(pw *os.File) {
	sz := pipeBufSize(pw)
	raw, err := pw.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		flags, _ := unix.FcntlInt(fd, unix.F_GETFL, 0)
		_, _ = unix.FcntlInt(fd, unix.F_SETFL, flags|unix.O_NONBLOCK)
		zeros := make([]byte, sz)
		for {
			n, err := unix.Write(int(fd), zeros)
			if n < 0 || err != nil {
				break
			}
			if n < len(zeros) {
				break
			}
		}
		_, _ = unix.FcntlInt(fd, unix.F_SETFL, flags)
	})
}
