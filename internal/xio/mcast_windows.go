//go:build windows

package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/parse"
)

func applyMembershipJoins(int, []membershipJoin) error {
	return fmt.Errorf("multicast join is not supported on Windows")
}

func applyMulticastNamedFD(_ int, _ multicastNamedKind, name string, _ parse.Option) error {
	return fmt.Errorf("%s: not supported on Windows", name)
}

func applySourceMembershipFD(_ int, _ membershipFamily, name, _ string) error {
	return fmt.Errorf("%s: not supported on Windows", name)
}
