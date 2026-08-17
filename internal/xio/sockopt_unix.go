//go:build unix

package xio

import "golang.org/x/sys/unix"

const (
	solSocket   = unix.SOL_SOCKET
	soReuseaddr = unix.SO_REUSEADDR
	soReuseport = unix.SO_REUSEPORT
	ipprotoIPv6 = unix.IPPROTO_IPV6
	ipv6V6only  = unix.IPV6_V6ONLY
)

func setSockoptInt(fd, level, opt, value int) error {
	return unix.SetsockoptInt(fd, level, opt, value)
}

func SetSockoptInt(fd, level, opt, value int) error {
	return setSockoptInt(fd, level, opt, value)
}
