//go:build linux || darwin

package fileopen

import (
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func setInheritedFDCloexec(fd int, g *xio.Global) {
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		if g != nil && g.Log != nil {
			g.Log.Warningf("fcntl(%d, F_SETFD, FD_CLOEXEC): %s", fd, err)
		}
	}
}
