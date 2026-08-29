//go:build linux || darwin

package xio

import (
	"os"
	"syscall"
)

// unixSocketpairLogged creates an AF_UNIX SOCK_STREAM pair and logs
// `socketpair(1, 1, 0, {a,b}) -> 0` (RECVFROM_FORK_LEAK).
func unixSocketpairLogged(g *Global) (a, b *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, err
	}
	if g != nil && g.Log != nil {
		g.Log.Infof("Generating socketpair that triggers parent when packet has been consumed")
		g.Log.Infof("socketpair(1, 1, 0, {%d,%d}) -> 0", fds[0], fds[1])
	}
	CloseOnExec(fds[0])
	CloseOnExec(fds[1])
	return os.NewFile(uintptr(fds[0]), "sp0"), os.NewFile(uintptr(fds[1]), "sp1"), nil
}
