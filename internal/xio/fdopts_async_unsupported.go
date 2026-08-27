//go:build unix && !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package xio

const (
	fdAsyncFlag    = 0
	FeatureFDAsync = false
)
