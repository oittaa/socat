//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package xio

import "golang.org/x/sys/unix"

// Compile-time proof that this platform defines B7200. Darwin/BSD encode the
// speed as the numeric baud (7200). Linux does not export unix.B7200.
var _ = unix.B7200

var platformBaudNamed = []baudOption{
	{"b7200", 7200},
}
