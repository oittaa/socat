//go:build darwin

package filan

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func openTestPTY() (master, slave *os.File, err error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	m := os.NewFile(uintptr(fd), "/dev/ptmx")
	defer func() {
		if err != nil {
			_ = m.Close()
		}
	}()
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, m.Fd(), uintptr(unix.TIOCPTYGRANT), 0); errno != 0 {
		err = errno
		return nil, nil, err
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, m.Fd(), uintptr(unix.TIOCPTYUNLK), 0); errno != 0 {
		err = errno
		return nil, nil, err
	}
	var buf [128]byte
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, m.Fd(), uintptr(unix.TIOCPTYGNAME), uintptr(unsafe.Pointer(&buf[0]))); errno != 0 { // #nosec G103 -- TIOCPTYGNAME writes the slave path
		err = errno
		return nil, nil, err
	}
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}
	sname := string(buf[:n])
	if sname == "" {
		err = fmt.Errorf("empty pty slave name")
		return nil, nil, err
	}
	s, err := os.OpenFile(sname, os.O_RDWR|syscall.O_NOCTTY, 0) // #nosec G304 -- path is TIOCPTYGNAME, not user input
	if err != nil {
		return nil, nil, fmt.Errorf("open slave %s: %w", sname, err)
	}
	return m, s, nil
}
