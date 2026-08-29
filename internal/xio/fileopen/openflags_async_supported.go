//go:build darwin

package fileopen

import "golang.org/x/sys/unix"

const (
	oAsyncFlag      = unix.O_ASYNC
	oAsyncSupported = true
)
