//go:build unix && !linux

package xio

import "golang.org/x/sys/unix"

// unix.B7200 exists on Darwin/BSD (numeric 7200). Linux glibc 2.41+ also
// defines B7200, but golang.org/x/sys/unix does not export it, so Linux does
// not advertise b7200 from this table.
var platformBaudNamed = []baudOption{
	{"b7200", 7200},
}

func setSpeed(t *unix.Termios, baud uint32, in, out bool) {
	b := termiosBits(baud)
	if in {
		t.Ispeed = b
	}
	if out {
		t.Ospeed = b
	}
}
