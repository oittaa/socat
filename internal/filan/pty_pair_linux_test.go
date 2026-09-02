//go:build linux

package filan

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func openTestPTY() (master, slave *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			_ = m.Close()
		}
	}()
	var unlock int32
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, m.Fd(), uintptr(unix.TIOCSPTLCK), uintptr(unsafe.Pointer(&unlock))); errno != 0 { // #nosec G103 -- TIOCSPTLCK takes an int pointer
		err = errno
		return nil, nil, err
	}
	var n uint32
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, m.Fd(), uintptr(unix.TIOCGPTN), uintptr(unsafe.Pointer(&n))); errno != 0 { // #nosec G103 -- TIOCGPTN writes the pts index
		err = errno
		return nil, nil, err
	}
	sname := "/dev/pts/" + strconv.Itoa(int(n))
	s, err := os.OpenFile(sname, os.O_RDWR|syscall.O_NOCTTY, 0) // #nosec G304 -- path is TIOCGPTN, not user input
	if err != nil {
		return nil, nil, fmt.Errorf("open slave %s: %w", sname, err)
	}
	return m, s, nil
}
