//go:build darwin

package xio

import "golang.org/x/sys/unix"

func setSpeed(t *unix.Termios, baud uint32, in, out bool) {
	b := termiosBits(baud)
	if in {
		t.Ispeed = b
	}
	if out {
		t.Ospeed = b
	}
}
