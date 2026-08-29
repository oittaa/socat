//go:build darwin

package netopen

import "golang.org/x/sys/unix"

// Darwin sockaddr_un requires sun_len.
func setUnixSockaddrLen(sa *unix.RawSockaddrUnix, n int) {
	if n < 0 {
		n = 0
	}
	if n > 255 {
		n = 255
	}
	sa.Len = uint8(n)
}
