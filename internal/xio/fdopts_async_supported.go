//go:build linux || darwin

package xio

import "golang.org/x/sys/unix"

const (
	fdAsyncFlag    = unix.O_ASYNC
	FeatureFDAsync = true
)
