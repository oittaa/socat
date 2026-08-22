//go:build !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package netopen

func enableUDPForkPortReuse(int) error { return nil }
