//go:build linux

package filan

import "golang.org/x/sys/unix"

func kernelSockaddrLen(_ *unix.RawSockaddrAny, namelen int) int {
	return namelen
}
