//go:build darwin || windows

package xio

func setCloexecRange(int) bool { return false }
