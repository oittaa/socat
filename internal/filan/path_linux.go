//go:build linux

package filan

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const (
	fionreadReq = unix.TIOCINQ
	libcNCCS    = 32
)

func fionread(fd int) (int, error) {
	n, err := unix.IoctlGetUint32(fd, fionreadReq)
	return int(int32(n)), err // #nosec G115 -- kernel returns signed 32-bit int
}

func getDumpTermios(fd int) (dumpTermios, error) {
	t, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return dumpTermios{}, err
	}
	return dumpTermios{
		Iflag: uint64(t.Iflag),
		Oflag: uint64(t.Oflag),
		Cflag: uint64(t.Cflag),
		Lflag: uint64(t.Lflag),
		Cc:    libcDisplayCC(t.Cc[:]),
	}, nil
}

// libcDisplayCC copies the architecture's kernel c_cc slice into a glibc
// NCCS=32 display buffer. Remaining entries are 0 (_POSIX_VDISABLE).
func libcDisplayCC(cc []byte) []byte {
	out := make([]byte, libcNCCS)
	copy(out, cc)
	return out
}

// FDPath returns the kernel path for fd, or empty if unknown.
func FDPath(fd int) string {
	p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return ""
	}
	return p
}

func statDev(st *unix.Stat_t) (uint64, uint64) {
	return st.Dev, st.Rdev
}
