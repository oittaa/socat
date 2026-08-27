//go:build windows

package xio

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

func notSocketError() error {
	return fmt.Errorf("%w", windows.WSAENOTSOCK)
}

func isNotSock(err error) bool {
	return errors.Is(err, windows.WSAENOTSOCK)
}
