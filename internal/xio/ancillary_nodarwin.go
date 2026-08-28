//go:build unix && !darwin

package xio

func ancillaryRecvSockoptPlatform(string) (level, opt int, ok bool) {
	return 0, 0, false
}

func handleIPv4CmsgBSD(int32, []byte, *Global) bool { return false }
