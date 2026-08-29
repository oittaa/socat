package testutil

import (
	"errors"

	"golang.org/x/sys/windows"
)

func retryableBindError(err error) bool {
	return errors.Is(err, windows.WSAEADDRINUSE) || errors.Is(err, windows.WSAEACCES)
}
