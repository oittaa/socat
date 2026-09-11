//go:build darwin

package xio

// Darwin FIONREAD: _IOR('f', 127, int) = 0x4004667f.
func fionreadRequest() uint { return 0x4004667f }
