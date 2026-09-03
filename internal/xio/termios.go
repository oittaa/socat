//go:build linux || darwin

package xio

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
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

type termiosSetFlags struct {
	word  int
	flags termiosBits
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

func parseTermiosBool(o parse.Option) (bool, error) {
	if !o.Has {
		return true, nil
	}
	switch strings.TrimSpace(o.Value) {
	case "0":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, fmt.Errorf("%s: boolean value must be 0 or 1", o.Name)
	}
}

func parseTermiosByte(name string, o parse.Option) (byte, error) {
	// The man page documents every control character as name=<byte>. A bare
	// flag is rejected here. Overflow clamps to 255.
	v := strings.TrimSpace(o.Value)
	if !o.Has || v == "" {
		return 0, fmt.Errorf("%s: value required", name)
	}
	n, err := strconv.ParseUint(v, 0, 8)
	if err == nil {
		return byte(n), nil
	}
	if errors.Is(err, strconv.ErrRange) {
		return 255, nil
	}
	return 0, fmt.Errorf("%s: invalid byte value %q", name, v)
}

func parseTermiosUint(name string, o parse.Option) (uint32, error) {
	v := strings.TrimSpace(o.Value)
	if !o.Has || v == "" {
		return 0, fmt.Errorf("option %q: missing numerical value", name)
	}
	n, err := strconv.ParseUint(v, 0, 32)
	if err != nil {
		// Distinguish a value with no numeric prefix from a valid prefix
		// followed by junk (different diagnostics).
		for i := len(v) - 1; i > 0; i-- {
			if _, prefixErr := strconv.ParseUint(v[:i], 0, 32); prefixErr == nil {
				return 0, fmt.Errorf("option %q: trailing garbage %q", name, v[i:])
			}
		}
		if v[0] < '0' || v[0] > '9' {
			return 0, fmt.Errorf("option %q: missing numerical value", name)
		}
		return 0, fmt.Errorf("%s: invalid unsigned value %q", name, v)
	}
	return uint32(n), nil
}

func parseTermiosField(o parse.Option, field termiosValue) (termiosBits, error) {
	n, err := parseTermiosUint(field.name, o)
	if err != nil {
		return 0, err
	}
	shifted64 := uint64(n) << field.shift
	if shifted64 > uint64(^termiosBits(0)) || shifted64&^uint64(field.mask) != 0 {
		return 0, fmt.Errorf("%s: invalid value %d", field.name, n)
	}
	shifted := termiosBits(shifted64)
	return shifted, nil
}

func parseTermiosSetFlags(o parse.Option) (termiosSetFlags, error) {
	v := strings.TrimSpace(o.Value)
	if !o.Has || v == "" {
		return termiosSetFlags{}, fmt.Errorf("%s: WORD:FLAGS value required", o.Name)
	}
	parts := strings.Split(v, ":")
	if len(parts) != 2 {
		return termiosSetFlags{}, fmt.Errorf("%s: expected WORD:FLAGS", o.Name)
	}
	word, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 0, 32)
	if err != nil || word < 0 || word > 3 {
		return termiosSetFlags{}, fmt.Errorf("%s: word must be 0..3", o.Name)
	}
	// Parse flags at host unsigned-long width, then truncate to tcflag_t when
	// the termios word is narrower.
	flags64, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 0, strconv.IntSize)
	if err != nil {
		return termiosSetFlags{}, fmt.Errorf("%s: invalid flags %q", o.Name, strings.TrimSpace(parts[1]))
	}
	flags := termiosBits(flags64) // #nosec G115 -- unsigned-long to tcflag_t truncation.
	return termiosSetFlags{word: int(word), flags: flags}, nil
}

func validateTermiosConst(o parse.Option) error {
	if o.Has {
		return fmt.Errorf("%s: no value permitted", o.Name)
	}
	return nil
}

// ValidateTermiosOption enforces the documented option type. Non-termios
// options are ignored.
func ValidateTermiosOption(o parse.Option) error {
	name := parse.CanonicalOptionName(o.Name)
	if isTermiosCombo(name) {
		return validateTermiosConst(o)
	}
	if f, ok := lookupTermiosFlag(name); ok {
		if f.clr != 0 {
			return validateTermiosConst(o)
		}
		_, err := parseTermiosBool(o)
		return err
	}
	if _, ok := lookupTermiosChar(name); ok {
		_, err := parseTermiosByte(name, o)
		return err
	}
	if _, ok := lookupBaud(name); ok {
		return validateTermiosConst(o)
	}
	if name == "ispeed" || name == "ospeed" {
		_, err := parseTermiosUint(name, o)
		return err
	}
	if field, ok := lookupTermiosValue(name); ok {
		_, err := parseTermiosField(o, field)
		return err
	}
	if name == "termios-setflags" {
		_, err := parseTermiosSetFlags(o)
		return err
	}
	if name == "tiocswinsz" {
		if !o.Has || strings.TrimSpace(o.Value) == "" {
			return fmt.Errorf("%s: COL:ROW value required", o.Name)
		}
		_, _, err := parseWinsz(o.Value)
		return err
	}
	if name == "ctty" {
		_, err := parseTermiosBool(o)
		return err
	}
	return nil
}

func isTermiosStateOption(name string) bool {
	if isTermiosCombo(name) || name == "ispeed" || name == "ospeed" || name == "termios-setflags" {
		return true
	}
	if _, ok := lookupTermiosFlag(name); ok {
		return true
	}
	if _, ok := lookupTermiosChar(name); ok {
		return true
	}
	if _, ok := lookupBaud(name); ok {
		return true
	}
	_, ok := lookupTermiosValue(name)
	return ok
}

func specHasTermiosState(s parse.Spec) bool {
	for _, o := range s.Options {
		if isTermiosStateOption(parse.CanonicalOptionName(o.Name)) {
			return true
		}
	}
	return false
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

func applyOneTermios(t *unix.Termios, o parse.Option) error {
	name := parse.CanonicalOptionName(o.Name)
	if isTermiosCombo(name) {
		applyCombo(t, name)
		return nil
	}
	if f, ok := lookupTermiosFlag(name); ok {
		if f.clr != 0 {
			setPattern(t, f.word, f.clr, f.mask)
			return nil
		}
		on, err := parseTermiosBool(o)
		if err != nil {
			return err
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
		setSpeed(t, baud, true, true)
		return nil
	}
	if name == "ispeed" || name == "ospeed" {
		n, err := parseTermiosUint(name, o)
		if err != nil {
			return err
		}
		setSpeed(t, n, name == "ispeed", name == "ospeed")
		return nil
	}
	if field, ok := lookupTermiosValue(name); ok {
		value, err := parseTermiosField(o, field)
		if err != nil {
			return err
		}
		setPattern(t, field.word, field.mask, value)
		return nil
	}
	if name == "termios-setflags" {
		value, err := parseTermiosSetFlags(o)
		if err != nil {
			return err
		}
		setTermiosWord(t, value.word, value.flags)
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

// ApplyTermios mutates fd termios from spec. Options are applied in
// command-line order. A termios state option on a non-TTY is an error;
// specs without termios state options remain valid on ordinary descriptors.
func ApplyTermios(fd int, s parse.Spec) error {
	if err := RejectUnsupportedTermios(s); err != nil {
		return err
	}
	for _, o := range s.Options {
		if err := ValidateTermiosOption(o); err != nil {
			return err
		}
	}
	if specHasTermiosState(s) {
		t, err := getTermios(fd)
		if err != nil {
			return fmt.Errorf("termios: %w", err)
		}
		for _, o := range s.Options {
			if !isTermiosStateOption(parse.CanonicalOptionName(o.Name)) {
				continue
			}
			if err := applyOneTermios(t, o); err != nil {
				return err
			}
		}
		if err := setTermios(fd, t); err != nil {
			return fmt.Errorf("termios: %w", err)
		}
	}
	if err := ApplyWinsz(fd, s); err != nil {
		return err
	}
	return ApplyCtty(fd, s)
}

// ApplyWinsz sets TIOCSWINSZ from tiocswinsz=COL:ROW.
func ApplyWinsz(fd int, s parse.Spec) error {
	for _, o := range s.Options {
		if parse.CanonicalOptionName(o.Name) != "tiocswinsz" {
			continue
		}
		col, row, err := parseWinsz(o.Value)
		if err != nil {
			return err
		}
		ws := unix.Winsize{Col: col, Row: row}
		if err := unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &ws); err != nil {
			return fmt.Errorf("tiocswinsz: %w", err)
		}
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
	for _, o := range s.Options {
		if parse.CanonicalOptionName(o.Name) != "ctty" {
			continue
		}
		enabled, err := parseTermiosBool(o)
		if err != nil {
			return err
		}
		if !enabled {
			continue
		}
		if err := unix.IoctlSetInt(fd, unix.TIOCSCTTY, 0); err != nil {
			// EPERM if already controlling / not session leader — ignore like setsid.
			if err != unix.EPERM {
				return fmt.Errorf("ctty: %w", err)
			}
		}
	}
	return nil
}

// AttachTermios saves tty state, applies spec, and restores on Opened.Close
// before the FD is closed.
func AttachTermios(o *Opened, fd int, s parse.Spec) error {
	var saved *unix.Termios
	if specHasTermiosState(s) {
		var err error
		saved, err = getTermios(fd)
		if err != nil {
			return fmt.Errorf("termios: %w", err)
		}
	}
	if err := ApplyTermios(fd, s); err != nil {
		return err
	}
	if saved == nil {
		return nil
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

// PTYWaitInterval is pty-interval (default 1s).
func PTYWaitInterval(s parse.Spec) time.Duration {
	if !s.HasOption("pty-interval") {
		return time.Second
	}
	return ParseTimeval(s.OptionValue("pty-interval", "1"))
}
