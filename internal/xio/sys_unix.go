//go:build linux || darwin

package xio

import "golang.org/x/sys/unix"

const oCloexec = unix.O_CLOEXEC

func CloseOnExec(fd int) { unix.CloseOnExec(fd) }

func ShutdownWrite(fd int) error { return unix.Shutdown(fd, unix.SHUT_WR) }

func SetNonblock(fd int, on bool) {
	fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return
	}
	if on {
		_, _ = unix.FcntlInt(uintptr(fd), unix.F_SETFL, fl|unix.O_NONBLOCK)
		return
	}
	_, _ = unix.FcntlInt(uintptr(fd), unix.F_SETFL, fl&^unix.O_NONBLOCK)
}

func Setsid() error {
	_, err := unix.Setsid()
	if err == unix.EPERM {
		return nil
	}
	return err
}
