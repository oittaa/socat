//go:build linux || darwin

package xio

import (
	"errors"
	"syscall"
)

func retryableTestBindError(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.EACCES)
}
