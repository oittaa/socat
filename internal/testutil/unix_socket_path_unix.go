//go:build linux || darwin

package testutil

func unixSocketTempRoot() string { return "/tmp" }
