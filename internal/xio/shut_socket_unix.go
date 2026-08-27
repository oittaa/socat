//go:build unix

package xio

import (
	"errors"
	"fmt"
	"syscall"
)

func notSocketError() error {
	return fmt.Errorf("%w", syscall.ENOTSOCK)
}

func isNotSock(err error) bool {
	return errors.Is(err, syscall.ENOTSOCK)
}
