//go:build darwin

package xio

func SetCloexecRange(int) bool { return false }
