//go:build darwin || windows

package xio

func interfaceProtocolFamily(int) bool { return false }
