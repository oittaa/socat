//go:build linux || darwin

package xio

func isTransientLockCreateError(error) bool { return false }
