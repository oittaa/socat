//go:build windows

package sockopt

import "github.com/oittaa/socat/internal/addrconfig"

func applyOwnerIoctlPlatform(int, addrconfig.NamedSocket, int) error {
	return errNamedOptUnsupported
}
