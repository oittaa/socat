//go:build windows

package xio

import "golang.org/x/sys/windows"

const oCloexec = 0

func CloseOnExec(int) {}

// ShutdownWrite is Winsock shutdown(SD_SEND). Classic XIOSHUT_DOWN calls
// shutdown(fd, SHUT_WR) on the socket; a no-op here made connected UDP
// shut-down silently do nothing because *net.UDPConn has no CloseWrite.
func ShutdownWrite(fd int) error {
	return windows.Shutdown(windows.Handle(fd), windows.SHUT_WR) // Winsock SD_SEND
}

func SetNonblock(int, bool) {}

func Setsid() error { return nil }
