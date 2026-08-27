//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd

package xio

import "golang.org/x/sys/unix"

const (
	fdAsyncFlag    = unix.O_ASYNC
	FeatureFDAsync = true
)
