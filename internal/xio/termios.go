//go:build unix

package xio

import (
	"fmt"
	"math"
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
	// clr, when non-zero, is a field mask: classic OFUNC_TERMIOS_PATTERN
	// (cs8, nl1, …). Apply clears clr then ORs mask. BOOL flags leave clr=0.
	clr termiosBits
}

type termiosCC struct {
	name string
	idx  int
}

// Flags we honor (classic names). Advertise only these.
// Classic baseline: https://repo.or.cz/socat.git tag-1.8.1.3
// (12c08bf66d709fba17035ce95d85bd218428d9ba); official master
// af5388c898c7bb60997935aee93c223deba60c4a has the same xio-termios.c.
var termiosFlags = []termiosFlag{
	{"ignbrk", wordI, termiosBits(unix.IGNBRK), 0},
	{"brkint", wordI, termiosBits(unix.BRKINT), 0},
	{"ignpar", wordI, termiosBits(unix.IGNPAR), 0},
	{"parmrk", wordI, termiosBits(unix.PARMRK), 0},
	{"inpck", wordI, termiosBits(unix.INPCK), 0},
	{"istrip", wordI, termiosBits(unix.ISTRIP), 0},
	{"inlcr", wordI, termiosBits(unix.INLCR), 0},
	{"igncr", wordI, termiosBits(unix.IGNCR), 0},
	{"icrnl", wordI, termiosBits(unix.ICRNL), 0},
	{"ixon", wordI, termiosBits(unix.IXON), 0},
	{"ixoff", wordI, termiosBits(unix.IXOFF), 0},
	{"ixany", wordI, termiosBits(unix.IXANY), 0},
	{"imaxbel", wordI, termiosBits(unix.IMAXBEL), 0},
	{"opost", wordO, termiosBits(unix.OPOST), 0},
	{"onlcr", wordO, termiosBits(unix.ONLCR), 0},
	{"ocrnl", wordO, termiosBits(unix.OCRNL), 0},
	{"onocr", wordO, termiosBits(unix.ONOCR), 0},
	{"onlret", wordO, termiosBits(unix.ONLRET), 0},
	{"cs5", wordC, termiosBits(unix.CS5), termiosBits(unix.CSIZE)},
	{"cs6", wordC, termiosBits(unix.CS6), termiosBits(unix.CSIZE)},
	{"cs7", wordC, termiosBits(unix.CS7), termiosBits(unix.CSIZE)},
	{"cs8", wordC, termiosBits(unix.CS8), termiosBits(unix.CSIZE)},
	{"cstopb", wordC, termiosBits(unix.CSTOPB), 0},
	{"cread", wordC, termiosBits(unix.CREAD), 0},
	{"parenb", wordC, termiosBits(unix.PARENB), 0},
	{"parodd", wordC, termiosBits(unix.PARODD), 0},
	{"hupcl", wordC, termiosBits(unix.HUPCL), 0},
	{"clocal", wordC, termiosBits(unix.CLOCAL), 0},
	{"crtscts", wordC, termiosBits(unix.CRTSCTS), 0},
	{"isig", wordL, termiosBits(unix.ISIG), 0},
	{"icanon", wordL, termiosBits(unix.ICANON), 0},
	{"echo", wordL, termiosBits(unix.ECHO), 0},
	{"echoe", wordL, termiosBits(unix.ECHOE), 0},
	{"echok", wordL, termiosBits(unix.ECHOK), 0},
	{"echonl", wordL, termiosBits(unix.ECHONL), 0},
	{"noflsh", wordL, termiosBits(unix.NOFLSH), 0},
	{"tostop", wordL, termiosBits(unix.TOSTOP), 0},
	{"echoctl", wordL, termiosBits(unix.ECHOCTL), 0},
	{"echoke", wordL, termiosBits(unix.ECHOKE), 0},
	{"iexten", wordL, termiosBits(unix.IEXTEN), 0},
}

// Linux glibc c_cc indices advertised in the tag-1.8.1.3 -hhh dump.
// HP-UX vdsusp/dsusp stays docs-only (not defined here).
var termiosChars = []termiosCC{
	{"vintr", unix.VINTR},
	{"vquit", unix.VQUIT},
	{"verase", unix.VERASE},
	{"vkill", unix.VKILL},
	{"veof", unix.VEOF},
	{"veol", unix.VEOL},
	{"veol2", unix.VEOL2},
	{"vmin", unix.VMIN},
	{"vtime", unix.VTIME},
	{"vstart", unix.VSTART},
	{"vstop", unix.VSTOP},
	{"vsusp", unix.VSUSP},
	{"vwerase", unix.VWERASE},
	{"vlnext", unix.VLNEXT},
	{"vdiscard", unix.VDISCARD},
	{"vreprint", unix.VREPRINT},
}

// termiosCharAliases are classic optionnames[] nicknames of termiosChars.
// Folded at parse time; listed in -hhh via TermiosHelpNames.
var termiosCharAliases = []string{
	"intr", "quit", "erase", "kill", "eof", "eol", "eol2",
	"min", "time", "start", "stop", "susp", "werase", "lnext",
	"discard", "reprint", "rprnt",
}

var termiosCombos = []string{"sane", "rawer", "raw", "cfmakeraw"}

type baudOption struct {
	name string
	baud uint32
}

var baudNamed = []baudOption{
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

func baudOptions() []baudOption {
	out := make([]baudOption, 0, len(baudNamed)+len(platformBaudNamed))
	out = append(out, baudNamed...)
	out = append(out, platformBaudNamed...)
	return out
}

func allTermiosFlags() []termiosFlag {
	out := make([]termiosFlag, 0, len(termiosFlags)+len(platformTermiosFlags))
	out = append(out, termiosFlags...)
	out = append(out, platformTermiosFlags...)
	return out
}

// TermiosHelpNames are option names we enforce (for -hh).
func TermiosHelpNames() []string {
	out := []string{
		"cfmakeraw", "raw", "rawer", "sane",
		"ispeed", "ospeed",
		"tiocswinsz", "winsz",
		"ctty", "tiocsctty",
		"pty-wait-slave", "wait-slave", "waitslave", "pty-interval", "ptmx", "openpty",
	}
	out = append(out, termiosCharAliases...)
	for _, c := range termiosChars {
		out = append(out, c.name)
	}
	for _, f := range allTermiosFlags() {
		out = append(out, f.name)
	}
	for _, b := range baudOptions() {
		out = append(out, b.name)
	}
	return out
}

func lookupTermiosFlag(name string) (termiosFlag, bool) {
	for _, f := range allTermiosFlags() {
		if f.name == name {
			return f, true
		}
	}
	return termiosFlag{}, false
}

func lookupTermiosChar(name string) (int, bool) {
	for _, c := range termiosChars {
		if c.name == name {
			return c.idx, true
		}
	}
	return 0, false
}

func lookupBaud(name string) (uint32, bool) {
	for _, b := range baudOptions() {
		if b.name == name {
			return b.baud, true
		}
	}
	return 0, false
}

func isTermiosCombo(name string) bool {
	for _, c := range termiosCombos {
		if c == name {
			return true
		}
	}
	return false
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

func setPattern(t *unix.Termios, word termiosWord, field, value termiosBits) {
	switch word {
	case wordI:
		t.Iflag &^= field
		t.Iflag |= value
	case wordO:
		t.Oflag &^= field
		t.Oflag |= value
	case wordC:
		t.Cflag &^= field
		t.Cflag |= value
	case wordL:
		t.Lflag &^= field
		t.Lflag |= value
	}
}

func optionBool(o parse.Option) bool {
	if !o.Has {
		return true
	}
	v := strings.ToLower(strings.TrimSpace(o.Value))
	if v == "" {
		return false
	}
	return v != "0" && v != "false" && v != "no" && v != "off"
}

func parseTermiosByte(name string, o parse.Option) (byte, error) {
	// Classic TYPE_BYTE (xioopts.c tag-1.8.1.3): bare flag → 1; assigned
	// value is strtoul base 0; overflow logs then uses UCHAR_MAX.
	if !o.Has {
		return 1, nil
	}
	v := strings.TrimSpace(o.Value)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(v, 0, 8)
	if err == nil {
		return byte(n), nil
	}
	if _, err64 := strconv.ParseUint(v, 0, 64); err64 == nil {
		return 255, nil
	}
	return 0, fmt.Errorf("%s: invalid byte value %q", name, v)
}

func applyCombo(t *unix.Termios, name string) {
	switch name {
	case "cfmakeraw":
		// Linux cfmakeraw(3) / classic OPT_TERMIOS_CFMAKERAW fallback.
		t.Iflag &^= termiosBits(unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
			unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON)
		t.Oflag &^= termiosBits(unix.OPOST)
		t.Lflag &^= termiosBits(unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN)
		t.Cflag &^= termiosBits(unix.CSIZE | unix.PARENB)
		t.Cflag |= termiosBits(unix.CS8)
		t.Cc[unix.VMIN] = 1
		t.Cc[unix.VTIME] = 0
	case "raw":
		// Classic OPT_RAW (not an alias of cfmakeraw): xio-termios.c
		// xiotermios_flagscomb, tag-1.8.1.3.
		t.Iflag &^= termiosBits(unix.IGNBRK|unix.BRKINT|unix.IGNPAR|unix.PARMRK|unix.INPCK|unix.ISTRIP|
			unix.INLCR|unix.IGNCR|unix.ICRNL|unix.IXON|unix.IXOFF|unix.IXANY|unix.IMAXBEL) | termiosIUCLC
		t.Oflag &^= termiosBits(unix.OPOST)
		t.Lflag &^= termiosBits(unix.ISIG|unix.ICANON) | termiosXCASE
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
		t.Iflag &^= termiosBits(unix.IGNBRK|unix.INLCR|unix.IGNCR|unix.IXOFF|unix.IXANY) | termiosIUCLC
		t.Iflag |= termiosBits(unix.BRKINT | unix.ICRNL | unix.IMAXBEL)
		t.Oflag &^= termiosOLCUC | termiosBits(unix.OCRNL|unix.ONOCR|unix.ONLRET) |
			termiosOFILL | termiosOFDEL | termiosNLDLY | termiosCRDLY | termiosTABDLY |
			termiosBSDLY | termiosVTDLY | termiosFFDLY
		t.Oflag |= termiosBits(unix.OPOST|unix.ONLCR) | termiosNL0 | termiosCR0 | termiosTAB0 |
			termiosBS0 | termiosVT0 | termiosFF0
		t.Cflag |= termiosBits(unix.CREAD)
		t.Lflag &^= termiosBits(unix.ECHONL|unix.NOFLSH|unix.TOSTOP) | termiosXCASE | termiosECHOPRT
		t.Lflag |= termiosBits(unix.ISIG | unix.ICANON | unix.IEXTEN | unix.ECHO | unix.ECHOE | unix.ECHOK | unix.ECHOCTL | unix.ECHOKE)
	}
}

func applyOneTermios(t *unix.Termios, o parse.Option) error {
	name := parse.CanonicalOptionName(o.Name)
	if isTermiosCombo(name) {
		if o.Has && !optionBool(o) {
			return nil
		}
		applyCombo(t, name)
		return nil
	}
	if f, ok := lookupTermiosFlag(name); ok {
		on := optionBool(o)
		if f.clr != 0 {
			if on {
				setPattern(t, f.word, f.clr, f.mask)
			}
			return nil
		}
		setFlag(t, f.word, f.mask, on)
		return nil
	}
	if idx, ok := lookupTermiosChar(name); ok {
		b, err := parseTermiosByte(name, o)
		if err != nil {
			return err
		}
		t.Cc[idx] = b
		return nil
	}
	if baud, ok := lookupBaud(name); ok {
		if optionBool(o) {
			setSpeed(t, baud, true, true)
		}
		return nil
	}
	if name == "ispeed" && o.Has {
		n, err := strconv.ParseUint(strings.TrimSpace(o.Value), 0, 32)
		if err == nil {
			setSpeed(t, uint32(n), true, false)
		}
		return nil
	}
	if name == "ospeed" && o.Has {
		n, err := strconv.ParseUint(strings.TrimSpace(o.Value), 0, 32)
		if err == nil {
			setSpeed(t, uint32(n), false, true)
		}
		return nil
	}
	return nil
}

func getTermios(fd int) (*unix.Termios, error) {
	return unix.IoctlGetTermios(fd, termiosGet)
}

func setTermios(fd int, t *unix.Termios) error {
	return unix.IoctlSetTermios(fd, termiosSet, t)
}

// ApplyTermios mutates fd termios from spec. No-op if fd is not a tty.
// Options are applied in command-line order at classic PH_FD (applyopts /
// OFUNC_TERMIOS_* in xioopts.c). Last occurrence wins for conflicting flags.
func ApplyTermios(fd int, s parse.Spec) error {
	if err := RejectUnsupportedTermios(s); err != nil {
		return err
	}
	t, err := getTermios(fd)
	if err != nil {
		return nil
	}
	for _, o := range s.Options {
		if err := applyOneTermios(t, o); err != nil {
			return err
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
	if masterFD < 0 || masterFD > math.MaxInt32 {
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
