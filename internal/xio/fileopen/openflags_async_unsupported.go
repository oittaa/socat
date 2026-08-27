//go:build unix && !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package fileopen

const (
	oAsyncFlag      = 0
	oAsyncSupported = false
)
