//go:build windows

package xio

import "github.com/oittaa/socat/internal/addrconfig"

func applyOwnerIoctlPlatform(int, addrconfig.NamedSocket, int) error {
	return errNamedOptUnsupported
}
