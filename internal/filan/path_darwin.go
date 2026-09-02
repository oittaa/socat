//go:build darwin

package filan

import (
	"bytes"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	termiosGet  = unix.TIOCGETA
	fionreadReq = 0x4004667f // FIONREAD
)

// FDPath returns the kernel path for fd, or empty if unknown.
func FDPath(fd int) string {
	var buf [1024]byte
	_, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), uintptr(unix.F_GETPATH), uintptr(unsafe.Pointer(&buf[0]))) // #nosec G103 -- F_GETPATH writes into a path buffer
	if errno != 0 {
		return ""
	}
	n := bytes.IndexByte(buf[:], 0)
	if n <= 0 {
		return ""
	}
	return string(buf[:n])
}
