//go:build unix

package xio

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

// FeatureTERMIOS is on when we apply and restore termios options.
var FeatureTERMIOS = true

type termiosWord int

const (
	wordI termiosWord = iota
	wordO
	wordC
	wordL
)

type termiosFlag struct {
	name string
	word termiosWord
	mask termiosBits
}

// Flags we honor (classic names). Advertise only these.
var termiosFlags = []termiosFlag{
	{"ignbrk", wordI, termiosBits(unix.IGNBRK)},
	{"brkint", wordI, termiosBits(unix.BRKINT)},
	{"ignpar", wordI, termiosBits(unix.IGNPAR)},
	{"parmrk", wordI, termiosBits(unix.PARMRK)},
	{"inpck", wordI, termiosBits(unix.INPCK)},
	{"istrip", wordI, termiosBits(unix.ISTRIP)},
	{"inlcr", wordI, termiosBits(unix.INLCR)},
	{"igncr", wordI, termiosBits(unix.IGNCR)},
	{"icrnl", wordI, termiosBits(unix.ICRNL)},
	{"ixon", wordI, termiosBits(unix.IXON)},
	{"ixoff", wordI, termiosBits(unix.IXOFF)},
	{"ixany", wordI, termiosBits(unix.IXANY)},
	{"imaxbel", wordI, termiosBits(unix.IMAXBEL)},
	{"opost", wordO, termiosBits(unix.OPOST)},
	{"onlcr", wordO, termiosBits(unix.ONLCR)},
	{"ocrnl", wordO, termiosBits(unix.OCRNL)},
	{"onocr", wordO, termiosBits(unix.ONOCR)},
	{"onlret", wordO, termiosBits(unix.ONLRET)},
	{"cs5", wordC, termiosBits(unix.CS5)},
	{"cs6", wordC, termiosBits(unix.CS6)},
	{"cs7", wordC, termiosBits(unix.CS7)},
	{"cs8", wordC, termiosBits(unix.CS8)},
	{"cstopb", wordC, termiosBits(unix.CSTOPB)},
	{"cread", wordC, termiosBits(unix.CREAD)},
	{"parenb", wordC, termiosBits(unix.PARENB)},
	{"parodd", wordC, termiosBits(unix.PARODD)},
	{"hupcl", wordC, termiosBits(unix.HUPCL)},
	{"clocal", wordC, termiosBits(unix.CLOCAL)},
	{"crtscts", wordC, termiosBits(unix.CRTSCTS)},
	{"isig", wordL, termiosBits(unix.ISIG)},
	{"icanon", wordL, termiosBits(unix.ICANON)},
	{"echo", wordL, termiosBits(unix.ECHO)},
	{"echoe", wordL, termiosBits(unix.ECHOE)},
	{"echok", wordL, termiosBits(unix.ECHOK)},
	{"echonl", wordL, termiosBits(unix.ECHONL)},
	{"noflsh", wordL, termiosBits(unix.NOFLSH)},
	{"tostop", wordL, termiosBits(unix.TOSTOP)},
	{"echoctl", wordL, termiosBits(unix.ECHOCTL)},
	{"echoke", wordL, termiosBits(unix.ECHOKE)},
	{"iexten", wordL, termiosBits(unix.IEXTEN)},
}

var baudNamed = []struct {
	name string
	baud uint32
}{
	{"b0", 0},
	{"b50", 50},
	{"b75", 75},
	{"b110", 110},
	{"b134", 134},
	{"b150", 150},
	{"b200", 200},
	{"b300", 300},
	{"b600", 600},
	{"b1200", 1200},
	{"b1800", 1800},
	{"b2400", 2400},
	{"b4800", 4800},
	{"b9600", 9600},
	{"b19200", 19200},
	{"b38400", 38400},
	{"b57600", 57600},
	{"b115200", 115200},
	{"b230400", 230400},
}

// TermiosHelpNames are option names we enforce (for -hh).
func TermiosHelpNames() []string {
	out := []string{
		"cfmakeraw", "raw", "rawer", "sane",
		"ispeed", "ospeed",
		"tiocswinsz", "winsz",
		"ctty", "tiocsctty",
		"pty-wait-slave", "wait-slave", "waitslave", "pty-interval",
		"ptmx", "openpty",
	}
	for _, f := range termiosFlags {
		out = append(out, f.name)
	}
	for _, b := range baudNamed {
		out = append(out, b.name)
	}
	return out
}

func setFlag(t *unix.Termios, word termiosWord, mask termiosBits, on bool) {
	switch word {
	case wordI:
		if on {
			t.Iflag |= mask
		} else {
			t.Iflag &^= mask
		}
	case wordO:
		if on {
			t.Oflag |= mask
		} else {
			t.Oflag &^= mask
		}
	case wordC:
		if on {
			t.Cflag |= mask
		} else {
			t.Cflag &^= mask
		}
	case wordL:
		if on {
			t.Lflag |= mask
		} else {
			t.Lflag &^= mask
		}
	}
}

func applyCombo(t *unix.Termios, name string) {
	switch name {
	case "cfmakeraw", "raw":
		t.Iflag &^= termiosBits(unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
			unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON)
		t.Oflag &^= termiosBits(unix.OPOST)
		t.Lflag &^= termiosBits(unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN)
		t.Cflag &^= termiosBits(unix.CSIZE | unix.PARENB)
		t.Cflag |= termiosBits(unix.CS8)
		t.Cc[unix.VMIN] = 1
		t.Cc[unix.VTIME] = 0
	case "rawer":
		t.Iflag = 0
		t.Oflag = 0
		t.Lflag = 0
		t.Cflag = termiosBits(unix.CREAD | unix.CS8)
		t.Cc[unix.VMIN] = 1
		t.Cc[unix.VTIME] = 0
	case "sane":
		t.Iflag &^= termiosBits(unix.IGNBRK | unix.INLCR | unix.IGNCR | unix.IXOFF | unix.IXANY)
		t.Iflag |= termiosBits(unix.BRKINT | unix.ICRNL | unix.IMAXBEL)
		t.Oflag &^= termiosBits(unix.OCRNL | unix.ONOCR | unix.ONLRET)
		t.Oflag |= termiosBits(unix.OPOST | unix.ONLCR)
		t.Cflag |= termiosBits(unix.CREAD)
		t.Lflag &^= termiosBits(unix.ECHONL | unix.NOFLSH | unix.TOSTOP)
		t.Lflag |= termiosBits(unix.ISIG | unix.ICANON | unix.IEXTEN | unix.ECHO | unix.ECHOE | unix.ECHOK | unix.ECHOCTL | unix.ECHOKE)
	}
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

func getTermios(fd int) (*unix.Termios, error) {
	return unix.IoctlGetTermios(fd, termiosGet)
}

func setTermios(fd int, t *unix.Termios) error {
	return unix.IoctlSetTermios(fd, termiosSet, t)
}

// ApplyTermios mutates fd termios from spec. No-op if fd is not a tty.
func ApplyTermios(fd int, s parse.Spec) error {
	t, err := getTermios(fd)
	if err != nil {
		return nil
	}
	for _, name := range []string{"sane", "rawer", "raw", "cfmakeraw"} {
		if !s.HasOption(name) {
			continue
		}
		o, _ := s.OptionNamed(name)
		if o.Has && !s.BoolOption(name) {
			continue
		}
		applyCombo(t, name)
	}
	for _, f := range termiosFlags {
		if !s.HasOption(f.name) {
			continue
		}
		on := s.BoolOption(f.name)
		if f.name == "cs5" || f.name == "cs6" || f.name == "cs7" || f.name == "cs8" {
			if on {
				t.Cflag &^= termiosBits(unix.CSIZE)
				t.Cflag |= f.mask
			}
			continue
		}
		setFlag(t, f.word, f.mask, on)
		if f.name == "echo" && !on {
			t.Lflag &^= termiosBits(unix.ECHONL)
		}
	}
	for _, b := range baudNamed {
		if s.HasOption(b.name) && s.BoolOption(b.name) {
			setSpeed(t, b.baud, true, true)
		}
	}
	if v := s.OptionValue("ispeed", ""); v != "" && s.HasOption("ispeed") {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			setSpeed(t, uint32(n), true, false)
		}
	}
	if v := s.OptionValue("ospeed", ""); v != "" && s.HasOption("ospeed") {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			setSpeed(t, uint32(n), false, true)
		}
	}
	if err := setTermios(fd, t); err != nil {
		return fmt.Errorf("termios: %w", err)
	}
	if err := ApplyWinsz(fd, s); err != nil {
		return err
	}
	return ApplyCtty(fd, s)
}

// ApplyWinsz sets TIOCSWINSZ from tiocswinsz=COL:ROW.
func ApplyWinsz(fd int, s parse.Spec) error {
	v := ""
	if s.HasOption("tiocswinsz") {
		v = s.OptionValue("tiocswinsz", "")
	}
	if v == "" || v == "1" {
		return nil
	}
	col, row, err := parseWinsz(v)
	if err != nil {
		return err
	}
	ws := unix.Winsize{Col: col, Row: row}
	if err := unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &ws); err != nil {
		return fmt.Errorf("tiocswinsz: %w", err)
	}
	return nil
}

func parseWinsz(v string) (col, row uint16, err error) {
	parts := strings.Split(v, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("tiocswinsz requires COL:ROW")
	}
	c, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("tiocswinsz col: %w", err)
	}
	r, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("tiocswinsz row: %w", err)
	}
	if c < 0 {
		c = 0
	}
	if r < 0 {
		r = 0
	}
	if c > 65535 {
		c = 65535
	}
	if r > 65535 {
		r = 65535
	}
	return uint16(c), uint16(r), nil
}

// ApplyCtty issues TIOCSCTTY when ctty is set.
func ApplyCtty(fd int, s parse.Spec) error {
	if !s.BoolOption("ctty") {
		return nil
	}
	if err := unix.IoctlSetInt(fd, unix.TIOCSCTTY, 0); err != nil {
		// EPERM if already controlling / not session leader — ignore like setsid.
		if err != unix.EPERM {
			return fmt.Errorf("ctty: %w", err)
		}
	}
	return nil
}

// AttachTermios saves tty state, applies spec, and restores on Opened.Close
// before the FD is closed.
func AttachTermios(o *Opened, fd int, s parse.Spec) error {
	saved, err := getTermios(fd)
	if err != nil {
		return nil
	}
	if err := ApplyTermios(fd, s); err != nil {
		return err
	}
	cp := *saved
	fdc := fd
	o.AddTTYRestore(func() {
		_ = setTermios(fdc, &cp)
	})
	return nil
}

// WaitPTYSlave polls the master until POLLHUP clears (a slave is open).
func WaitPTYSlave(masterFD int, interval time.Duration) error {
	if interval <= 0 {
		interval = time.Second
	}
	if masterFD < 0 {
		return fmt.Errorf("pty-wait-slave: %w", unix.EBADF)
	}
	pfd := []unix.PollFd{{Fd: int32(masterFD), Events: unix.POLLIN | unix.POLLOUT}}
	for {
		_, err := unix.Poll(pfd, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("pty-wait-slave: %w", err)
		}
		if pfd[0].Revents&unix.POLLHUP == 0 {
			return nil
		}
		time.Sleep(interval)
	}
}

// PTYWaitInterval is pty-interval (classic default 1s).
func PTYWaitInterval(s parse.Spec) time.Duration {
	if !s.HasOption("pty-interval") {
		return time.Second
	}
	return ParseTimeval(s.OptionValue("pty-interval", "1"))
}
