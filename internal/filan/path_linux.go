//go:build linux

package filan

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const (
	termiosGet  = unix.TCGETS2
	fionreadReq = unix.TIOCINQ
)

// FDPath returns the kernel path for fd, or empty if unknown.
func FDPath(fd int) string {
	p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return ""
	}
	return p
}
