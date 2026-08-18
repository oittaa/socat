//go:build windows

package netopen

import (
	"fmt"
	"syscall"
)

type syscallConn interface {
	SyscallConn() (syscall.RawConn, error)
}

func joinMulticast(syscallConn, string) error {
	return fmt.Errorf("multicast join is not supported on Windows")
}
