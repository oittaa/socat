//go:build windows

package xio

import "golang.org/x/sys/windows"

const (
	solSocket   = windows.SOL_SOCKET
	soReuseaddr = windows.SO_REUSEADDR
	soReuseport = 0
	ipprotoIPv6 = windows.IPPROTO_IPV6
	ipv6V6only  = windows.IPV6_V6ONLY
)

func setSockoptInt(fd, level, opt, value int) error {
	return windows.SetsockoptInt(windows.Handle(fd), level, opt, value)
}

func SetSockoptInt(fd, level, opt, value int) error {
	return setSockoptInt(fd, level, opt, value)
}
