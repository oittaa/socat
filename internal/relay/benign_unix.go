//go:build linux || darwin

package relay

func isBenignPlatformClose(error) bool { return false }
