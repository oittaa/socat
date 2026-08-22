//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package netopen

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// BSD kernels require SO_REUSEPORT on every socket that binds an identical
// UDP address and port. UDP fork sessions need this on both the parent listener
// and each connected child socket.
func enableUDPForkPortReuse(fd int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		return fmt.Errorf("UDP fork reuseport: %w", err)
	}
	return nil
}
