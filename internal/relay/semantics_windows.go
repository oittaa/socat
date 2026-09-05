package relay

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// Winsock SO_TYPE is not exported by x/sys/windows.
const socketTypeOption = 0x1008

func descriptorSemantics(c syscall.Conn) IOSemantics {
	raw, err := c.SyscallConn()
	if err != nil {
		return UnknownIO
	}
	kind := UnknownIO
	err = raw.Control(func(fd uintptr) {
		typ, err := windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, socketTypeOption)
		if err == nil {
			if typ == windows.SOCK_STREAM {
				kind = ByteStreamIO
			} else {
				kind = MessageIO
			}
		} else {
			var mode uint32
			if windows.GetConsoleMode(windows.Handle(fd), &mode) == nil {
				kind = ByteStreamIO
			}
		}
	})
	if err != nil {
		return UnknownIO
	}
	return kind
}
