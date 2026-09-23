//go:build linux

package sockopt

import "github.com/oittaa/socat/internal/addrconfig"

func ancillaryRecvSockoptPlatform(addrconfig.AncillaryOption) (level, opt int, ok bool) {
	return 0, 0, false
}

func handleIPv4CmsgDarwin(int32, []byte, Session) bool { return false }
