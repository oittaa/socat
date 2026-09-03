//go:build darwin

package filan

import (
	"bytes"
	"unsafe"

	"golang.org/x/sys/unix"
)

const fionreadReq = 0x4004667f // FIONREAD

func fionread(fd int) (int, error) {
	n, err := unix.IoctlGetInt(fd, fionreadReq)
	return int(int32(n)), err // #nosec G115 -- kernel returns signed 32-bit int
}

func getDumpTermios(fd int) (dumpTermios, error) {
	t, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		return dumpTermios{}, err
	}
	cc := make([]byte, len(t.Cc))
	copy(cc, t.Cc[:])
	return dumpTermios{
		Iflag: t.Iflag,
		Oflag: t.Oflag,
		Cflag: t.Cflag,
		Lflag: t.Lflag,
		Cc:    cc,
	}, nil
}

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

func statDev(st *unix.Stat_t) (uint64, uint64) {
	return uint64(uint32(st.Dev)), uint64(uint32(st.Rdev)) // #nosec G115 -- Darwin dev_t is int32 containing 32-bit device bits; preserve bit representation
}
