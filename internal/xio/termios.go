//go:build linux || darwin

package xio

import (
	"fmt"
	"math"
	"math/bits"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
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
	// clr, when non-zero, is a field mask (cs8, nl1, …). Apply clears clr
	// then ORs mask. BOOL flags leave clr=0.
	clr termiosBits
}

type termiosCC struct {
	name string
	idx  int
}

type termiosValue struct {
	name  string
	word  termiosWord
	mask  termiosBits
	shift uint
}

// Flags we honor. Advertise only these.
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

// Linux glibc c_cc indices we advertise. HP-UX vdsusp/dsusp stays docs-only.
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

func allTermiosChars() []termiosCC {
	out := make([]termiosCC, 0, len(termiosChars)+len(platformTermiosChars))
	out = append(out, termiosChars...)
	out = append(out, platformTermiosChars...)
	return out
}

// termiosCharAliases are nicknames of termiosChars.
// Folded at parse time; listed in -hhh via TermiosHelpNames.
var termiosCharAliases = []string{
	"intr", "quit", "erase", "kill", "eof", "eol", "eol2",
	"min", "time", "start", "stop", "susp", "werase", "lnext",
	"discard", "reprint", "rprnt",
}

var termiosFlagAliases = []string{
	"crterase", "crtkill", "ctlecho", "hup", "prterase", "tandem",
}

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

func allTermiosValues() []termiosValue {
	out := make([]termiosValue, 0, len(posixTermiosValueTable)+len(platformTermiosValues))
	out = append(out, posixTermiosValueTable...)
	out = append(out, platformTermiosValues...)
	return out
}

// termiosTwoBitShift reports the shift of a 2-bit termios field (mask must
// equal 3<<shift). Masks that mix unrelated bits, such as Darwin TABDLY
// (TAB3 aliases OXTABS), are not a field.
func termiosTwoBitShift(mask termiosBits) (uint, bool) {
	if mask == 0 {
		return 0, false
	}
	shift := uint(bits.TrailingZeros64(uint64(mask)))
	if mask != termiosBits(3)<<shift {
		return 0, false
	}
	return shift, true
}

func posixTermiosValues() []termiosValue {
	var out []termiosValue
	if shift, ok := termiosTwoBitShift(termiosCRDLY); ok {
		out = append(out, termiosValue{name: "crdly", word: wordO, mask: termiosCRDLY, shift: shift})
	}
	if shift, ok := termiosTwoBitShift(termiosTABDLY); ok {
		out = append(out, termiosValue{name: "tabdly", word: wordO, mask: termiosTABDLY, shift: shift})
	}
	if shift, ok := termiosTwoBitShift(termiosBits(unix.CSIZE)); ok {
		out = append(out, termiosValue{name: "csize", word: wordC, mask: termiosBits(unix.CSIZE), shift: shift})
	}
	return out
}

var posixTermiosValueTable = posixTermiosValues()

// TermiosHelpNames are option names we enforce (for -hh).
func TermiosHelpNames() []string {
	out := []string{
		"cfmakeraw", "termios-cfmakeraw", "raw", "rawer", "termios-rawer", "sane",
		"termios-setflags", "setflags",
		"ispeed", "ospeed",
		"tiocswinsz", "winsz",
		"ctty", "tiocsctty",
		"pty-wait-slave", "wait-slave", "waitslave", "pty-interval", "ptmx", "openpty",
	}
	out = append(out, termiosCharAliases...)
	out = append(out, platformTermiosCharAliases...)
	out = append(out, termiosFlagAliases...)
	for _, c := range allTermiosChars() {
		out = append(out, c.name)
	}
	for _, f := range allTermiosFlags() {
		out = append(out, f.name)
	}
	for _, v := range allTermiosValues() {
		out = append(out, v.name)
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
	for _, c := range allTermiosChars() {
		if c.name == name {
			return c.idx, true
		}
	}
	return 0, false
}

func lookupTermiosValue(name string) (termiosValue, bool) {
	for _, v := range allTermiosValues() {
		if v.name == name {
			return v, true
		}
	}
	return termiosValue{}, false
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

func applyCombo(t *unix.Termios, name string) {
	switch name {
	case "raw":
		// raw is not cfmakeraw: it clears the legacy input-processing set
		// and canonical/signal processing, but leaves ECHO, IEXTEN, CSIZE,
		// and parity unchanged.
		t.Iflag &^= termiosBits(unix.IGNBRK | unix.BRKINT | unix.IGNPAR | unix.PARMRK |
			unix.INPCK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL |
			unix.IXON | unix.IXOFF | unix.IXANY | unix.IMAXBEL)
		t.Iflag &^= rawExtraIflag
		t.Oflag &^= termiosBits(unix.OPOST)
		t.Lflag &^= termiosBits(unix.ISIG | unix.ICANON)
		t.Lflag &^= rawExtraLflag
		t.Cc[unix.VMIN] = 1
		t.Cc[unix.VTIME] = 0
	case "cfmakeraw":
		// Linux cfmakeraw(3) fallback.
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

func setTermiosWord(t *unix.Termios, word int, flags termiosBits) {
	switch termiosWord(word) {
	case wordI:
		t.Iflag = flags
	case wordO:
		t.Oflag = flags
	case wordC:
		t.Cflag = flags
	case wordL:
		t.Lflag = flags
	}
}

func getTermios(fd int) (*unix.Termios, error) {
	return unix.IoctlGetTermios(fd, termiosGet)
}

func setTermios(fd int, t *unix.Termios) error {
	return unix.IoctlSetTermios(fd, termiosSet, t)
}

// ApplyConfiguredTermios applies decoded terminal operations in their source
// order. The platform table resolves prepared action identities to termios
// fields; no option value grammar is interpreted here.
func ApplyConfiguredTermios(fd int, config addrconfig.Terminal) error {
	if hasConfiguredTermiosState(config) {
		t, err := getTermios(fd)
		if err != nil {
			return fmt.Errorf("termios: %w", err)
		}
		for _, action := range config.Actions {
			if err := applyConfiguredTermiosAction(t, action); err != nil {
				return err
			}
		}
		if err := setTermios(fd, t); err != nil {
			return fmt.Errorf("termios: %w", err)
		}
	}
	for _, action := range config.Actions {
		if action.Kind != addrconfig.TerminalActionWinSize {
			continue
		}
		ws := unix.Winsize{Col: action.Col, Row: action.Row}
		if err := unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &ws); err != nil {
			return fmt.Errorf("tiocswinsz: %w", err)
		}
	}
	if !config.CTTY.Set || !config.CTTY.Value {
		return nil
	}
	if err := unix.IoctlSetInt(fd, unix.TIOCSCTTY, 0); err != nil && err != unix.EPERM {
		return fmt.Errorf("ctty: %w", err)
	}
	return nil
}

func hasConfiguredTermiosState(config addrconfig.Terminal) bool {
	for _, action := range config.Actions {
		if action.Kind != addrconfig.TerminalActionWinSize {
			return true
		}
	}
	return false
}

func applyConfiguredTermiosAction(t *unix.Termios, action addrconfig.TerminalAction) error {
	switch action.Kind {
	case addrconfig.TerminalActionCombo:
		applyCombo(t, action.Name)
	case addrconfig.TerminalActionFlag:
		flag, ok := lookupTermiosFlag(action.Name)
		if !ok {
			return nil
		}
		if flag.clr != 0 {
			setPattern(t, flag.word, flag.clr, flag.mask)
			return nil
		}
		setFlag(t, flag.word, flag.mask, action.Enabled)
	case addrconfig.TerminalActionChar:
		idx, ok := lookupTermiosChar(action.Name)
		if !ok {
			return nil
		}
		if action.Value > math.MaxUint8 {
			return fmt.Errorf("%s: invalid byte value %d", action.Name, action.Value)
		}
		t.Cc[idx] = byte(action.Value)
	case addrconfig.TerminalActionSpeed:
		switch action.Name {
		case "ispeed":
			setSpeed(t, action.Value, true, false)
		case "ospeed":
			setSpeed(t, action.Value, false, true)
		default:
			setSpeed(t, action.Value, true, true)
		}
	case addrconfig.TerminalActionField:
		field, ok := lookupTermiosValue(action.Name)
		if !ok {
			return nil
		}
		setPattern(t, field.word, field.mask, termiosBits(action.Value)<<field.shift)
	case addrconfig.TerminalActionSetFlags:
		setTermiosWord(t, int(action.Word), termiosBits(action.Flags)) // #nosec G115 -- decoder bounds the word and preserves the platform flag bit pattern.
	}
	return nil
}

// AttachConfiguredTermios saves, applies, and restores typed terminal state.
func AttachConfiguredTermios(o *Opened, fd int, config addrconfig.Terminal) error {
	var saved *unix.Termios
	if hasConfiguredTermiosState(config) {
		var err error
		saved, err = getTermios(fd)
		if err != nil {
			return fmt.Errorf("termios: %w", err)
		}
	}
	if err := ApplyConfiguredTermios(fd, config); err != nil {
		return err
	}
	if saved == nil {
		return nil
	}
	cp := *saved
	o.AddTTYRestore(func() { _ = setTermios(fd, &cp) })
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
