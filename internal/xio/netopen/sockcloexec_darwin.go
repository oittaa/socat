//go:build darwin

package netopen

import "golang.org/x/sys/unix"

func acceptCloexec(fd int) (int, error) {
	nfd, _, err := unix.Accept(fd)
	if err != nil {
		return -1, err
	}
	unix.CloseOnExec(nfd)
	return nfd, nil
}
