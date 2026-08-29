//go:build windows

package xio

func applyOwnerIoctlPlatform(int, string, int) error {
	return errNamedOptUnsupported
}
