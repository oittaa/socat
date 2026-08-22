//go:build !unix

package relay

func isWouldBlock(error) bool { return false }
