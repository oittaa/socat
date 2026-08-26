//go:build windows

package xio

import "fmt"

func applyMembershipJoins(int, []membershipJoin) error {
	return fmt.Errorf("multicast join is not supported on Windows")
}
