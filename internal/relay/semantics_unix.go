//go:build linux || darwin

package relay

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func descriptorSemantics(c syscall.Conn) IOSemantics {
	raw, err := c.SyscallConn()
	if err != nil {
		return UnknownIO
	}
	kind := UnknownIO
	err = raw.Control(func(fd uintptr) {
		typ, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
		if err == nil {
			if typ == unix.SOCK_STREAM {
				kind = ByteStreamIO
			} else {
				kind = MessageIO
			}
		} else if _, err := unix.IoctlGetTermios(int(fd), terminalGetAttr); err == nil {
			kind = ByteStreamIO
		}
	})
	if err != nil {
		return UnknownIO
	}
	return kind
}
