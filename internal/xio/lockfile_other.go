//go:build !windows

package xio

func isTransientLockCreateError(error) bool { return false }
