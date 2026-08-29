//go:build linux || darwin

package testutil

import (
	"errors"
	"syscall"
)

func retryableBindError(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.EACCES)
}
