//go:build !linux

package xio

func setCloexecRange(int) bool { return false }
