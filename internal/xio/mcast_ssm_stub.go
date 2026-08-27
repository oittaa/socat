//go:build unix && !(linux || darwin || freebsd)

package xio

import "fmt"

func applySourceMembershipFD(int, membershipFamily, name, spec string) error {
	return fmt.Errorf("%s: not supported on this platform", name)
}
