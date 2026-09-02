//go:build darwin

package filan

import "golang.org/x/sys/unix"

func kernelSockaddrLen(rsa *unix.RawSockaddrAny, namelen int) int {
	if rsa != nil && rsa.Addr.Len != 0 {
		return int(rsa.Addr.Len)
	}
	return namelen
}
