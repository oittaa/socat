package addrconfig

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

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

func decodeTerminal(a *Address, o parse.Option, name string) (bool, error) {
	appendAction := func(action TerminalAction) {
		action.Name = name
		a.Terminal.Actions = append(a.Terminal.Actions, action)
	}
	switch name {
	case "link":
		value, err := requiredString(o)
		if err != nil {
			return true, fmt.Errorf("link: path required")
		}
		a.Terminal.Link = OptionalString{Set: true, Value: value}
		return true, nil
	case "pty-wait-slave":
		return true, setActive(&a.Terminal.WaitSlave, o)
	case "pty-interval":
		value := optionText(o)
		d, err := ParseDuration(value)
		if err != nil {
			d = 0
		}
		a.Terminal.WaitInterval = OptionalDuration{Set: true, Value: d}
		return true, nil
	case "sitout-eio":
		if !o.Has || strings.TrimSpace(o.Value) == "" {
			return true, fmt.Errorf("sitout-eio: option requires a value")
		}
		d, err := ParseDuration(o.Value)
		if err != nil || d < 0 {
			return true, fmt.Errorf("sitout-eio: invalid timeval %q", o.Value)
		}
		a.Terminal.SitoutEIO = OptionalDuration{Set: true, Value: d}
		return true, nil
	case "ctty":
		value, err := optionalBool(o)
		if err != nil {
			return true, fmt.Errorf("%s: boolean value must be 0 or 1", o.Name)
		}
		a.Terminal.CTTY = value
		a.Process.CTTY = value
		return true, nil
	case "raw", "rawer", "cfmakeraw", "sane":
		if o.Has {
			return true, fmt.Errorf("%s: no value permitted", o.Name)
		}
		appendAction(TerminalAction{Kind: TerminalActionCombo})
		return true, nil
	case "termios-setflags":
		word, flags, err := terminalSetFlags(o)
		if err != nil {
			return true, err
		}
		appendAction(TerminalAction{Kind: TerminalActionSetFlags, Word: word, Flags: flags})
		return true, nil
	case "tiocswinsz":
		col, row, err := terminalWinSize(o)
		if err != nil {
			return true, err
		}
		appendAction(TerminalAction{Kind: TerminalActionWinSize, Col: col, Row: row})
		return true, nil
	case "ispeed", "ospeed":
		value, err := terminalUint(name, o)
		if err != nil {
			return true, err
		}
		appendAction(TerminalAction{Kind: TerminalActionSpeed, Value: value})
		return true, nil
	}
	if terminalComboName(name) {
		return false, nil
	}
	if terminalCharName(name) {
		value, err := terminalByte(name, o)
		if err != nil {
			return true, err
		}
		appendAction(TerminalAction{Kind: TerminalActionChar, Value: uint32(value)})
		return true, nil
	}
	if baud, ok := terminalBaud(name); ok {
		if o.Has {
			return true, fmt.Errorf("%s: no value permitted", o.Name)
		}
		appendAction(TerminalAction{Kind: TerminalActionSpeed, Value: baud})
		return true, nil
	}
	if terminalFieldName(name) {
		value, err := terminalUint(name, o)
		if err != nil {
			return true, err
		}
		if value > 3 {
			return true, fmt.Errorf("%s: invalid value %d", name, value)
		}
		appendAction(TerminalAction{Kind: TerminalActionField, Value: value})
		return true, nil
	}
	if terminalFlagName(name) {
		if terminalConstantFlagName(name) {
			if o.Has {
				return true, fmt.Errorf("%s: no value permitted", o.Name)
			}
			appendAction(TerminalAction{Kind: TerminalActionFlag, Enabled: true})
			return true, nil
		}
		value, err := optionalBool(o)
		if err != nil {
			return true, fmt.Errorf("%s: boolean value must be 0 or 1", o.Name)
		}
		appendAction(TerminalAction{Kind: TerminalActionFlag, Enabled: value.Value})
		return true, nil
	}
	return false, nil
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

func terminalByte(name string, o parse.Option) (byte, error) {
	if !o.Has || strings.TrimSpace(o.Value) == "" {
		return 0, fmt.Errorf("%s: value required", name)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(o.Value), 0, 8)
	if err == nil {
		return byte(n), nil
	}
	if errors.Is(err, strconv.ErrRange) {
		return 255, nil
	}
	return 0, fmt.Errorf("%s: invalid byte value %q", name, o.Value)
}

func terminalUint(name string, o parse.Option) (uint32, error) {
	value := strings.TrimSpace(o.Value)
	if !o.Has || value == "" {
		return 0, fmt.Errorf("option %q: missing numerical value", name)
	}
	n, err := strconv.ParseUint(value, 0, 32)
	if err != nil {
		for i := len(value) - 1; i > 0; i-- {
			if _, prefixErr := strconv.ParseUint(value[:i], 0, 32); prefixErr == nil {
				return 0, fmt.Errorf("option %q: trailing garbage %q", name, value[i:])
			}
		}
		if value[0] < '0' || value[0] > '9' {
			return 0, fmt.Errorf("option %q: missing numerical value", name)
		}
		return 0, fmt.Errorf("%s: invalid unsigned value %q", name, value)
	}
	return uint32(n), nil
}

func terminalSetFlags(o parse.Option) (uint8, uint64, error) {
	value := strings.TrimSpace(o.Value)
	if !o.Has || value == "" {
		return 0, 0, fmt.Errorf("%s: WORD:FLAGS value required", o.Name)
	}
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("%s: expected WORD:FLAGS", o.Name)
	}
	word, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 0, 8)
	if err != nil || word > 3 {
		return 0, 0, fmt.Errorf("%s: word must be 0..3", o.Name)
	}
	flags, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 0, strconv.IntSize)
	if err != nil {
		return 0, 0, fmt.Errorf("%s: invalid flags %q", o.Name, strings.TrimSpace(parts[1]))
	}
	return uint8(word), flags, nil
}

func terminalWinSize(o parse.Option) (uint16, uint16, error) {
	if !o.Has || strings.TrimSpace(o.Value) == "" {
		return 0, 0, fmt.Errorf("%s: COL:ROW value required", o.Name)
	}
	parts := strings.Split(o.Value, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("tiocswinsz requires COL:ROW")
	}
	col, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("tiocswinsz col: %w", err)
	}
	row, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("tiocswinsz row: %w", err)
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
