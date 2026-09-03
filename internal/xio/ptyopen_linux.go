//go:build linux

package xio

import (
	"fmt"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

func init() { FeaturePTY = true }

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
	if err = unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		return nil, nil, err
	}

	// Slave name /dev/pts/N
	n, err := unix.IoctlGetUint32(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		return nil, nil, err
	}
	sname := "/dev/pts/" + strconv.FormatUint(uint64(n), 10)

	s, err := os.OpenFile(sname, os.O_RDWR|syscall.O_NOCTTY, 0) // #nosec G304 -- slave path comes from TIOCGPTN, not from user input
	if err != nil {
		return nil, nil, fmt.Errorf("open slave %s: %w", sname, err)
	}
	return m, s, nil
}
