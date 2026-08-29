//go:build linux || darwin

package fileopen

import (
	"os"
	"syscall"

	"github.com/oittaa/socat/internal/xio"
)

const oNonblock = syscall.O_NONBLOCK

func mkfifo(path string, mode uint32) error { return syscall.Mkfifo(path, mode) }

func socketpairFiles(typ int) (a, b *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, typ, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[0]), "socketpair0"), os.NewFile(uintptr(fds[1]), "socketpair1"), nil
}

func clearNonblock(f *os.File) { xio.SetNonblock(int(f.Fd()), false) }
