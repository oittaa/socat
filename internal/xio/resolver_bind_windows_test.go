package xio

import (
	"errors"

	"golang.org/x/sys/windows"
)

func retryableTestBindError(err error) bool {
	return errors.Is(err, windows.WSAEADDRINUSE) || errors.Is(err, windows.WSAEACCES)
}
