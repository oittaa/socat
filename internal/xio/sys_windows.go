//go:build windows

package xio

import "golang.org/x/sys/windows"

const oCloexec = 0

// soType is Winsock SO_TYPE (getsockopt SOL_SOCKET). x/sys/windows does not
// export it. Value from WinSock2.h.
const soType = 0x1008

func CloseOnExec(int) {}

// ShutdownWrite is Winsock shutdown(SD_SEND). Classic XIOSHUT_DOWN calls
// Shutdown(fd, how) (xioshutdown.c, tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same tree). A no-op here
// made connected UDP shut-down silently do nothing because *net.UDPConn has
// no CloseWrite.
//
// Probe SO_TYPE before shutdown. Microsoft documents that getsockopt SO_TYPE
// returns WSAENOTSOCK for a non-socket descriptor. Calling shutdown(SD_SEND)
// directly on an os.Pipe handle can return WSAENOTCONN instead (GitHub
// windows-amd64), which would conflate a pipe with a genuine unconnected
// socket. A real socket returns its type, then shutdown runs and preserves
// WSAENOTCONN.
func ShutdownWrite(fd int) error {
	h := windows.Handle(fd)
	if _, err := windows.GetsockoptInt(h, windows.SOL_SOCKET, soType); err != nil {
		return err
	}
	return windows.Shutdown(h, windows.SHUT_WR) // Winsock SD_SEND
}

func SetNonblock(int, bool) {}

func Setsid() error { return nil }
