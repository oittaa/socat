//go:build darwin

package cli

import "golang.org/x/sys/unix"

func ptyTermios(fd int) (*unix.Termios, error) {
	return unix.IoctlGetTermios(fd, unix.TIOCGETA)
}
