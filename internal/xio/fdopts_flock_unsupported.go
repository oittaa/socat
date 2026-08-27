//go:build aix

package xio

import "golang.org/x/sys/unix"

const FeatureFlock = false

func flockFD(_ int, _ int) error {
	return unix.ENOSYS
}
