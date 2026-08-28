//go:build darwin || freebsd || openbsd || netbsd || dragonfly || aix

package netopen

import "golang.org/x/sys/unix"

// setUnixSockaddrLen is classic HAVE_STRUCT_SOCKADDR_SALEN sun_len.
// socket_un_init sets sun_len = sizeof(sockaddr_un); xiosetunix then
// overwrites it with the calculated length only when tight. Passing n
// (sizeof when untight, calculated when tight) matches both branches.
// tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same.
func setUnixSockaddrLen(sa *unix.RawSockaddrUnix, n int) {
	if n < 0 {
		n = 0
	}
	if n > 255 {
		n = 255
	}
	sa.Len = uint8(n)
}
