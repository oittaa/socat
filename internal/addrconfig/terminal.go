package addrconfig

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/optionmeta"
	"github.com/oittaa/socat/internal/parse"
)

// Terminal holds terminal setup and PTY policy. Actions retain source order.
type Terminal struct {
	Actions      []TerminalAction
	Link         OptionalString
	WaitSlave    OptionalBool
	WaitInterval OptionalDuration
	SitoutEIO    OptionalDuration
	CTTY         OptionalBool
}

// TerminalActionKind identifies one termios update.
type TerminalActionKind uint8

const (
	TerminalActionCombo TerminalActionKind = iota + 1
	TerminalActionFlag
	TerminalActionChar
	TerminalActionSpeed
	TerminalActionField
	TerminalActionSetFlags
	TerminalActionWinSize
)

// TerminalAction is one decoded terminal update.
type TerminalAction struct {
	Kind    TerminalActionKind
	Name    string
	Enabled bool
	Value   uint32
	Word    uint8
	Flags   uint64
	Col     uint16
	Row     uint16
}

func terminalConstantFlagName(name string) bool {
	switch name {
	case "cs5", "cs6", "cs7", "cs8", "nl0", "nl1", "cr0", "cr1", "cr2", "cr3", "tab0", "tab1", "tab2", "tab3", "xtabs", "bs0", "bs1", "vt0", "vt1", "ff0", "ff1":
		return true
	}
	return false
}

func terminalComboName(name string) bool {
	return name == "raw" || name == "rawer" || name == "cfmakeraw" || name == "sane"
}

func terminalCharName(name string) bool {
	switch name {
	case "vintr", "vquit", "verase", "vkill", "veof", "veol", "veol2", "vmin", "vtime", "vstart", "vstop", "vsusp", "vwerase", "vlnext", "vdiscard", "vreprint", "vswtc":
		return true
	}
	return false
}

func terminalFieldName(name string) bool {
	return name == "crdly" || name == "tabdly" || name == "csize"
}

// TermiosValueKind is the grammar for a termios spelling that is not a catalog entry.
func TermiosValueKind(name string) optionmeta.Kind {
	if terminalComboName(name) || terminalConstantFlagName(name) {
		return optionmeta.KindNoValueName
	}
	if _, ok := terminalBaud(name); ok {
		return optionmeta.KindNoValueName
	}
	if terminalCharName(name) {
		return optionmeta.KindTermiosByte
	}
	if terminalFieldName(name) {
		return optionmeta.KindTermiosField
	}
	if terminalFlagName(name) {
		return optionmeta.KindBool
	}
	return optionmeta.KindNone
}

func terminalFlagName(name string) bool {
	switch name {
	case "ignbrk", "brkint", "ignpar", "parmrk", "inpck", "istrip", "inlcr", "igncr", "icrnl", "ixon", "ixoff", "ixany", "imaxbel", "opost", "onlcr", "ocrnl", "onocr", "onlret", "cs5", "cs6", "cs7", "cs8", "cstopb", "cread", "parenb", "parodd", "hupcl", "clocal", "crtscts", "isig", "icanon", "echo", "echoe", "echok", "echonl", "noflsh", "tostop", "echoctl", "echoke", "iexten", "iuclc", "olcuc", "xcase", "pendin", "echoprt", "flusho", "ofill", "ofdel", "nl0", "nl1", "nldly", "cr0", "cr1", "cr2", "cr3", "tab0", "tab1", "tab2", "tab3", "xtabs", "bs0", "bs1", "bsdly", "vt0", "vt1", "vtdly", "ff0", "ff1", "ffdly":
		return true
	}
	return false
}

func terminalBaud(name string) (uint32, bool) {
	if len(name) < 2 || name[0] != 'b' {
		return 0, false
	}
	n, err := strconv.ParseUint(name[1:], 10, 32)
	if err != nil {
		return 0, false
	}
	switch n {
	case 0, 50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 7200, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 500000, 576000, 921600, 1000000, 1152000, 1500000, 2000000, 2500000, 3000000, 3500000, 4000000:
		return uint32(n), true
	}
	return 0, false
}

func terminalByte(o parse.Option) (byte, error) {
	if !o.Has || strings.TrimSpace(o.Value) == "" {
		return 0, optionValueError(o, "requires a value", "")
	}
	n, err := strconv.ParseUint(strings.TrimSpace(o.Value), 0, 8)
	if err == nil {
		return byte(n), nil
	}
	if errors.Is(err, strconv.ErrRange) {
		return 255, nil
	}
	return 0, optionValueError(o, "invalid value", strconv.Quote(o.Value))
}

func terminalUint(o parse.Option) (uint32, error) {
	value := strings.TrimSpace(o.Value)
	if !o.Has || value == "" {
		return 0, optionValueError(o, "invalid value", "missing numerical value")
	}
	n, err := strconv.ParseUint(value, 0, 32)
	if err != nil {
		for i := len(value) - 1; i > 0; i-- {
			if _, prefixErr := strconv.ParseUint(value[:i], 0, 32); prefixErr == nil {
				return 0, optionValueError(o, "invalid value", fmt.Sprintf("trailing garbage %q", value[i:]))
			}
		}
		if value[0] < '0' || value[0] > '9' {
			return 0, optionValueError(o, "invalid value", "missing numerical value")
		}
		return 0, optionValueError(o, "invalid value", strconv.Quote(value))
	}
	return uint32(n), nil
}

func terminalSetFlags(o parse.Option) (uint8, uint64, error) {
	value := strings.TrimSpace(o.Value)
	if !o.Has || value == "" {
		return 0, 0, optionValueError(o, "requires a value", "WORD:FLAGS")
	}
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return 0, 0, optionValueError(o, "invalid value", "expected WORD:FLAGS")
	}
	word, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 0, 8)
	if err != nil || word > 3 {
		return 0, 0, optionValueError(o, "invalid value", "word must be 0..3")
	}
	flags, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 0, strconv.IntSize)
	if err != nil {
		return 0, 0, optionValueError(o, "invalid value", fmt.Sprintf("invalid flags %q", strings.TrimSpace(parts[1])))
	}
	return uint8(word), flags, nil
}

func terminalWinSize(o parse.Option) (uint16, uint16, error) {
	if !o.Has || strings.TrimSpace(o.Value) == "" {
		return 0, 0, optionValueError(o, "requires a value", "COL:ROW")
	}
	parts := strings.Split(o.Value, ":")
	if len(parts) != 2 {
		return 0, 0, optionValueError(o, "invalid value", "requires COL:ROW")
	}
	col, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, optionValueError(o, "invalid value", strconv.Quote(o.Value))
	}
	row, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, optionValueError(o, "invalid value", strconv.Quote(o.Value))
	}
	if col < 0 {
		col = 0
	} else if col > math.MaxUint16 {
		col = math.MaxUint16
	}
	if row < 0 {
		row = 0
	} else if row > math.MaxUint16 {
		row = math.MaxUint16
	}
	return uint16(col), uint16(row), nil
}
