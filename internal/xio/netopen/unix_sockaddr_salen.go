//go:build darwin || freebsd || openbsd || netbsd || dragonfly || aix

package netopen

import "golang.org/x/sys/unix"

// setUnixSockaddrLen is classic HAVE_STRUCT_SOCKADDR_SALEN sun_len, set only
// when unix-tightsocklen is tight (xio-unix.c xiosetunix).
func setUnixSockaddrLen(sa *unix.RawSockaddrUnix, n int) {
	if n < 0 {
		n = 0
	}
	if n > 255 {
		n = 255
	}
	sa.Len = uint8(n)
}
