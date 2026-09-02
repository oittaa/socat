//go:build linux

package filan

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	fionreadReq = unix.TIOCINQ
	libcNCCS    = 32
)

// libcTermios matches glibc <termios.h> (NCCS=32). TCGETS copies the kernel
// termios (19 control characters) into the front; remaining c_cc stay 0
// (_POSIX_VDISABLE), matching tcgetattr.
type libcTermios struct {
	Iflag uint32
	Oflag uint32
	Cflag uint32
	Lflag uint32
	Line  uint8
	Cc    [libcNCCS]uint8
}

func getDumpTermios(fd int) (dumpTermios, error) {
	var t libcTermios
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TCGETS), uintptr(unsafe.Pointer(&t))) // #nosec G103 -- TCGETS writes libc termios
	if errno != 0 {
		return dumpTermios{}, errno
	}
	return dumpTermios{
		Iflag: t.Iflag,
		Oflag: t.Oflag,
		Cflag: t.Cflag,
		Lflag: t.Lflag,
		Cc:    t.Cc[:],
	}, nil
}

// FDPath returns the kernel path for fd, or empty if unknown.
func FDPath(fd int) string {
	p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return ""
	}
	return p
}
