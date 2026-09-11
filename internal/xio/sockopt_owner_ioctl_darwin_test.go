//go:build darwin

package xio

import "testing"

// FIOGETOWN SET works; GET does not copy out. F_GETOWN / SIOCGPGRP cover the owner.
func assertFIOGETOWN(*testing.T, int, int) {}
