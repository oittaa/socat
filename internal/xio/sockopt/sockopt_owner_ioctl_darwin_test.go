//go:build darwin

package sockopt

import "testing"

// FIOGETOWN writes so_pgid and returns before copyout. F_GETOWN and
// SIOCGPGRP cover the owner. This stays in package sockopt so the shared
// unix test does not assert the ioctl result.
func assertFIOGETOWN(*testing.T, int, int) {}
