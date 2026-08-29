//go:build linux

package xio

import "golang.org/x/sys/unix"

var platformBaudNamed = []baudOption{
	// glibc 2.41+ exposes B7200 as the numeric rate while x/sys/unix does not
	// export it. Use Linux BOTHER with c_ispeed/c_ospeed for a real 7200-baud
	// setting rather than omitting the advertised option.
	{"b7200", 7200},
	{"b460800", 460800},
	{"b500000", 500000},
	{"b576000", 576000},
	{"b921600", 921600},
	{"b1000000", 1000000},
	{"b1152000", 1152000},
	{"b1500000", 1500000},
	{"b2000000", 2000000},
	{"b2500000", 2500000},
	{"b3000000", 3000000},
	{"b3500000", 3500000},
	{"b4000000", 4000000},
}

func linuxBaudCode(baud uint32) (termiosBits, bool) {
	var code uint32
	switch baud {
	case 0:
		code = unix.B0
	case 50:
		code = unix.B50
	case 75:
		code = unix.B75
	case 110:
		code = unix.B110
	case 134:
		code = unix.B134
	case 150:
		code = unix.B150
	case 200:
		code = unix.B200
	case 300:
		code = unix.B300
	case 600:
		code = unix.B600
	case 1200:
		code = unix.B1200
	case 1800:
		code = unix.B1800
	case 2400:
		code = unix.B2400
	case 4800:
		code = unix.B4800
	case 9600:
		code = unix.B9600
	case 19200:
		code = unix.B19200
	case 38400:
		code = unix.B38400
	case 57600:
		code = unix.B57600
	case 115200:
		code = unix.B115200
	case 230400:
		code = unix.B230400
	case 460800:
		code = unix.B460800
	case 500000:
		code = unix.B500000
	case 576000:
		code = unix.B576000
	case 921600:
		code = unix.B921600
	case 1000000:
		code = unix.B1000000
	case 1152000:
		code = unix.B1152000
	case 1500000:
		code = unix.B1500000
	case 2000000:
		code = unix.B2000000
	case 2500000:
		code = unix.B2500000
	case 3000000:
		code = unix.B3000000
	case 3500000:
		code = unix.B3500000
	case 4000000:
		code = unix.B4000000
	default:
		return termiosBits(baud), false
	}
	return termiosBits(code), true
}

func setSpeed(t *unix.Termios, baud uint32, in, out bool) {
	value := termiosBits(baud)
	if code, ok := linuxBaudCode(baud); ok {
		value = code
		if in {
			t.Cflag &^= termiosBits(unix.CIBAUD)
			t.Cflag |= (code << 16) & termiosBits(unix.CIBAUD)
		}
		if out {
			t.Cflag &^= termiosBits(unix.CBAUD)
			t.Cflag |= code & termiosBits(unix.CBAUD)
		}
	} else {
		// TCSETS2 uses BOTHER plus the numeric c_ispeed/c_ospeed fields for
		// rates without a legacy kernel B* encoding (including B7200).
		if in {
			t.Cflag &^= termiosBits(unix.CIBAUD)
			t.Cflag |= (termiosBits(unix.BOTHER) << 16) & termiosBits(unix.CIBAUD)
		}
		if out {
			t.Cflag &^= termiosBits(unix.CBAUD)
			t.Cflag |= termiosBits(unix.BOTHER) & termiosBits(unix.CBAUD)
		}
	}
	if in {
		t.Ispeed = value
	}
	if out {
		t.Ospeed = value
	}
}
