//go:build windows

package relay

func isWouldBlock(error) bool { return false }
