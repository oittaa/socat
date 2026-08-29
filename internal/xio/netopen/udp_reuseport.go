//go:build linux || windows

package netopen

func enableUDPForkPortReuse(int) error { return nil }
