//go:build darwin

package xio

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func init() { FeaturePTY = true }

// openPTYPair allocates a master/slave PTY pair (macOS /dev/ptmx).
func OpenPTYPair() (master, slave *os.File, err error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	m := os.NewFile(uintptr(fd), "/dev/ptmx")
	defer func() {
		if err != nil {
			_ = m.Close()
		}
	}()

	// Grant access to the slave.
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, m.Fd(), uintptr(unix.TIOCPTYGRANT), 0); errno != 0 {
		err = errno
		return nil, nil, err
	}
	// Unlock slave.
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, m.Fd(), uintptr(unix.TIOCPTYUNLK), 0); errno != 0 {
		err = errno
		return nil, nil, err
	}
	// Slave path via TIOCPTYGNAME.
	var buf [128]byte
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, m.Fd(), uintptr(unix.TIOCPTYGNAME), uintptr(unsafe.Pointer(&buf[0]))); errno != 0 {
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

	s, err := os.OpenFile(sname, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open slave %s: %w", sname, err)
	}
	return m, s, nil
}
