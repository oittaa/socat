//go:build aix || solaris

package xio

func applyOwnerIoctlPlatform(int, string, int) error {
	return errNamedOptUnsupported
}
