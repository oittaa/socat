//go:build linux

package xio

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// openPTYPair allocates a master/slave PTY pair (linux /dev/ptmx).
func OpenPTYPair() (master, slave *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			_ = m.Close()
		}
	}()

	// Unlock slave.
	var unlock int32
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, m.Fd(), uintptr(unix.TIOCSPTLCK), uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		err = errno
		return nil, nil, err
	}

	// Slave name /dev/pts/N
	var n uint32
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, m.Fd(), uintptr(unix.TIOCGPTN), uintptr(unsafe.Pointer(&n))); errno != 0 {
		err = errno
		return nil, nil, err
	}
	sname := "/dev/pts/" + strconv.Itoa(int(n))

	s, err := os.OpenFile(sname, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open slave %s: %w", sname, err)
	}
	return m, s, nil
}
