//go:build darwin || windows

package xio

import (
	"fmt"
)

func applyFreebindValue(int, int) error {
	return fmt.Errorf("ip-freebind: not supported on this platform")
}

func applyTransparentValue(int, int) error {
	return fmt.Errorf("ip-transparent: not supported on this platform")
}

func applyMTUDiscoveryValue(_ int, _ membershipFamily, name string, _ int) error {
	return fmt.Errorf("%s: not supported on this platform", name)
}
