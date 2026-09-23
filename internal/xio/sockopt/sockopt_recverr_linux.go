//go:build linux

package sockopt

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func recvErrSupported() bool { return true }

func applyRecvErrValue(fd int, n int) error {
	if err := SetSockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, n); err != nil {
		return fmt.Errorf("ip-recverr: %w", err)
	}
	return nil
}
