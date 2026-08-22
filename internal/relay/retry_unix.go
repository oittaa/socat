//go:build unix

package relay

import (
	"errors"

	"golang.org/x/sys/unix"
)

func isWouldBlock(err error) bool {
	return errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK)
}
