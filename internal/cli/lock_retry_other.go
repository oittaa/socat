//go:build !windows

package cli

func isTransientLockCreateError(error) bool { return false }
