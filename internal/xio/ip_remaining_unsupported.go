//go:build darwin || windows

package xio

import (
	"fmt"
)

func applyRouterAlertValue(_ int, _ int, spelling string) error {
	if spelling == "" {
		spelling = "ip-router-alert"
	}
	return fmt.Errorf("%s: not supported on this platform", spelling)
}
