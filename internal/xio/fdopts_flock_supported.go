//go:build unix && !aix

package xio

import "golang.org/x/sys/unix"

const FeatureFlock = true

func flockFD(fd int, how int) error {
	return unix.Flock(fd, how)
}
