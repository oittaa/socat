//go:build windows

package xio

const oCloexec = 0

func CloseOnExec(int) {}

func ShutdownWrite(int) error { return nil }

func SetNonblock(int, bool) {}

func Setsid() error { return nil }
