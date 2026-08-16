package xio

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
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
	mask uint32
}

// Flags we honor (classic names). Advertise only these.
var termiosFlags = []termiosFlag{
	{"ignbrk", wordI, unix.IGNBRK},
	{"brkint", wordI, unix.BRKINT},
	{"ignpar", wordI, unix.IGNPAR},
	{"parmrk", wordI, unix.PARMRK},
	{"inpck", wordI, unix.INPCK},
	{"istrip", wordI, unix.ISTRIP},
	{"inlcr", wordI, unix.INLCR},
	{"igncr", wordI, unix.IGNCR},
	{"icrnl", wordI, unix.ICRNL},
	{"ixon", wordI, unix.IXON},
	{"ixoff", wordI, unix.IXOFF},
	{"ixany", wordI, unix.IXANY},
	{"imaxbel", wordI, unix.IMAXBEL},
	{"opost", wordO, unix.OPOST},
	{"onlcr", wordO, unix.ONLCR},
	{"ocrnl", wordO, unix.OCRNL},
	{"onocr", wordO, unix.ONOCR},
	{"onlret", wordO, unix.ONLRET},
	{"cs5", wordC, unix.CS5},
	{"cs6", wordC, unix.CS6},
	{"cs7", wordC, unix.CS7},
	{"cs8", wordC, unix.CS8},
	{"cstopb", wordC, unix.CSTOPB},
	{"cread", wordC, unix.CREAD},
	{"parenb", wordC, unix.PARENB},
	{"parodd", wordC, unix.PARODD},
	{"hupcl", wordC, unix.HUPCL},
	{"clocal", wordC, unix.CLOCAL},
	{"crtscts", wordC, unix.CRTSCTS},
	{"isig", wordL, unix.ISIG},
	{"icanon", wordL, unix.ICANON},
	{"echo", wordL, unix.ECHO},
	{"echoe", wordL, unix.ECHOE},
	{"echok", wordL, unix.ECHOK},
	{"echonl", wordL, unix.ECHONL},
	{"noflsh", wordL, unix.NOFLSH},
	{"tostop", wordL, unix.TOSTOP},
	{"echoctl", wordL, unix.ECHOCTL},
	{"echoke", wordL, unix.ECHOKE},
	{"iexten", wordL, unix.IEXTEN},
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

func setFlag(t *unix.Termios, word termiosWord, mask uint32, on bool) {
	p := (*uint32)(nil)
	switch word {
	case wordI:
		p = &t.Iflag
	case wordO:
		p = &t.Oflag
	case wordC:
		p = &t.Cflag
	case wordL:
		p = &t.Lflag
	}
	if p == nil {
		return
	}
	if on {
		*p |= mask
	} else {
		*p &^= mask
	}
}

func applyCombo(t *unix.Termios, name string) {
	switch name {
	case "cfmakeraw", "raw":
		t.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
			unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
		t.Oflag &^= unix.OPOST
		t.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
		t.Cflag &^= unix.CSIZE | unix.PARENB
		t.Cflag |= unix.CS8
		t.Cc[unix.VMIN] = 1
		t.Cc[unix.VTIME] = 0
	case "rawer":
		t.Iflag = 0
		t.Oflag = 0
		t.Lflag = 0
		t.Cflag = unix.CREAD | unix.CS8
		t.Cc[unix.VMIN] = 1
		t.Cc[unix.VTIME] = 0
	case "sane":
		t.Iflag &^= unix.IGNBRK | unix.INLCR | unix.IGNCR | unix.IXOFF | unix.IXANY
		t.Iflag |= unix.BRKINT | unix.ICRNL | unix.IMAXBEL
		t.Oflag &^= unix.OCRNL | unix.ONOCR | unix.ONLRET
		t.Oflag |= unix.OPOST | unix.ONLCR
		t.Cflag |= unix.CREAD
		t.Lflag &^= unix.ECHONL | unix.NOFLSH | unix.TOSTOP
		t.Lflag |= unix.ISIG | unix.ICANON | unix.IEXTEN | unix.ECHO | unix.ECHOE | unix.ECHOK | unix.ECHOCTL | unix.ECHOKE
	}
}

func setSpeed(t *unix.Termios, baud uint32, in, out bool) {
	if in {
		t.Ispeed = baud
	}
	if out {
		t.Ospeed = baud
	}
}

// ApplyTermios mutates fd termios from spec. No-op if fd is not a tty.
func ApplyTermios(fd int, s parse.Spec) error {
	t, err := unix.IoctlGetTermios(fd, unix.TCGETS)
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
				t.Cflag &^= unix.CSIZE
				t.Cflag |= f.mask
			}
			continue
		}
		setFlag(t, f.word, f.mask, on)
		if f.name == "echo" && !on {
			t.Lflag &^= unix.ECHONL
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
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, t); err != nil {
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
	saved, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil
	}
	if err := ApplyTermios(fd, s); err != nil {
		return err
	}
	cp := *saved
	fdc := fd
	o.AddTTYRestore(func() {
		_ = unix.IoctlSetTermios(fdc, unix.TCSETS, &cp)
	})
	return nil
}

// WaitPTYSlave polls the master until POLLHUP clears (a slave is open).
func WaitPTYSlave(masterFD int, interval time.Duration) error {
	if interval <= 0 {
		interval = time.Second
	}
	fd, ok := relay.PollFd(masterFD, unix.POLLIN|unix.POLLOUT)
	if !ok {
		return fmt.Errorf("pty-wait-slave: %w", unix.EBADF)
	}
	pfd := []unix.PollFd{fd}
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
