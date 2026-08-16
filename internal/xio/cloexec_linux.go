//go:build linux

package xio

import "golang.org/x/sys/unix"

func setCloexecRange(from int) bool {
	return unix.CloseRange(uint(from), ^uint(0), unix.CLOSE_RANGE_CLOEXEC) == nil
}
