package addrconfig

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// File is decoded descriptor and filesystem configuration.
type File struct {
	Access      FileAccess
	Create      OptionalBool
	Exclusive   bool
	AppendSet   bool
	Append      bool
	Truncate    bool
	Nonblock    bool
	Actions     []FileAction
	Umask       OptionalUint32
	UnlinkEarly OptionalBool
	UnlinkLate  OptionalBool
	UnlinkClose OptionalBool
	LockSet     bool
	LockWait    bool
	LockPath    string
}

// FileAccess is an open access mode.
type FileAccess uint8

const (
	FileAccessDefault FileAccess = iota
	FileAccessRead
	FileAccessWrite
	FileAccessReadWrite
)

// FileActionKind identifies one after-open action.
type FileActionKind uint8

const (
	FileActionPerm FileActionKind = iota + 1
	FileActionUser
	FileActionGroup
	FileActionFlock
	FileActionAppend
	FileActionAsync
	FileActionTruncate
	FileActionSeekStart
	FileActionSeekCurrent
	FileActionSeekEnd
	FileActionPermLate
	FileActionUserLate
	FileActionGroupLate
	FileActionCloexec
	FileActionNoAtime
	FileActionPipeSize
	FileActionFSFlag
	FileActionLock
	FileActionIoctl
	FileActionPermEarly
	FileActionUserEarly
	FileActionGroupEarly
	FileActionUnlink
	FileActionNoInherit
	FileActionOpenFlag
)

// FileAction is one filesystem operation in source order.
type FileAction struct {
	Kind      FileActionKind
	Name      string
	Enabled   bool
	Mode      uint32
	Offset    int64
	Value     int
	Text      string
	Request   uint32
	Bytes     []byte
	ValueKind uint8
}

// Process holds EXEC/SYSTEM/SHELL choices. Commands stay positional.
type Process struct {
	Pipes         OptionalBool
	PTY           OptionalBool
	Stderr        OptionalBool
	SetSID        OptionalBool
	CTTY          OptionalBool
	Dash          OptionalBool
	SetPGID       OptionalInt
	FDIn          OptionalInt
	FDOut         OptionalInt
	Shell         OptionalString
	Chdir         OptionalString
	ParentSignals []ParentSignal
}

// ParentSignal is one parent-to-child signal pass-through.
type ParentSignal uint8

const (
	ParentSignalNone ParentSignal = iota
	ParentSignalHUP
	ParentSignalINT
	ParentSignalQUIT
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

func decodeFileProcess(a *Address, o parse.Option) (bool, error) {
	name := optionIdentity(o)
	appendAction := func(action FileAction) {
		action.Name = o.OriginalSpelling()
		a.File.Actions = append(a.File.Actions, action)
	}
	switch name {
	case "rdonly", "wronly", "rdwr":
		if activeBool(o).Value {
			switch name {
			case "rdonly":
				a.File.Access = FileAccessRead
			case "wronly":
				a.File.Access = FileAccessWrite
			default:
				a.File.Access = FileAccessReadWrite
			}
		}
		return true, nil
	case "creat":
		a.File.Create = activeBool(o)
		return true, nil
	case "excl":
		a.File.Exclusive = activeBool(o).Value
		return true, nil
	case "append":
		enabled := activeBool(o).Value
		a.File.AppendSet = true
		a.File.Append = enabled
		appendAction(FileAction{Kind: FileActionAppend, Enabled: enabled})
		return true, nil
	case "trunc":
		a.File.Truncate = activeBool(o).Value
		return true, nil
	case "nonblock":
		a.File.Nonblock = activeBool(o).Value
		return true, nil
	case "o-direct", "o-sync", "o-dsync", "o-rsync", "o-noctty", "o-nofollow", "o-directory", "o-largefile":
		appendAction(FileAction{Kind: FileActionOpenFlag, Text: name, Enabled: activeBool(o).Value})
		return true, nil
	case "async":
		enabled := activeBool(o).Value
		appendAction(FileAction{Kind: FileActionAsync, Text: name, Enabled: enabled})
		return true, nil
	case "perm", "perm-late", "perm-early":
		mode, err := fileMode(o, 0o7777)
		if err != nil {
			return true, err
		}
		kind := FileActionPerm
		switch name {
		case "perm-late":
			kind = FileActionPermLate
		case "perm-early":
			kind = FileActionPermEarly
		}
		appendAction(FileAction{Kind: kind, Mode: mode})
		return true, nil
	case "user", "group", "user-late", "group-late", "user-early", "group-early":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		kind := FileActionUser
		switch name {
		case "group":
			kind = FileActionGroup
		case "user-late":
			kind = FileActionUserLate
		case "group-late":
			kind = FileActionGroupLate
		case "user-early":
			kind = FileActionUserEarly
		case "group-early":
			kind = FileActionGroupEarly
		}
		appendAction(FileAction{Kind: kind, Text: value})
		return true, nil
	case "ftruncate":
		n, err := nonnegativeInt64(o)
		if err != nil {
			return true, err
		}
		appendAction(FileAction{Kind: FileActionTruncate, Offset: n})
		return true, nil
	case "lseek", "seek-cur", "seek-end":
		n, err := seekOffset(o)
		if err != nil {
			return true, err
		}
		var kind FileActionKind
		switch name {
		case "lseek":
			kind = FileActionSeekStart
		case "seek-cur":
			kind = FileActionSeekCurrent
		case "seek-end":
			kind = FileActionSeekEnd
		}
		appendAction(FileAction{Kind: kind, Offset: n})
		return true, nil
	case "flock", "flock-nb", "flock-sh", "flock-sh-nb", "setlk", "setlkw", "setlk-rd", "setlkw-rd":
		kind, value := FileActionFlock, 1
		switch name {
		case "flock-nb":
			value = 2
		case "flock-sh":
			value = 3
		case "flock-sh-nb":
			value = 4
		case "setlk":
			kind, value = FileActionLock, 1
		case "setlkw":
			kind, value = FileActionLock, 2
		case "setlk-rd":
			kind, value = FileActionLock, 3
		case "setlkw-rd":
			kind, value = FileActionLock, 4
		}
		appendAction(FileAction{Kind: kind, Enabled: activeBool(o).Value, Value: value})
		return true, nil
	case "cloexec":
		enabled, err := optionalBool(o)
		if err != nil {
			return true, err
		}
		appendAction(FileAction{Kind: FileActionCloexec, Enabled: enabled.Value})
		return true, nil
	case "noinherit":
		appendAction(FileAction{Kind: FileActionNoInherit, Enabled: activeBool(o).Value})
		return true, nil
	case "o-noatime":
		appendAction(FileAction{Kind: FileActionNoAtime, Enabled: activeBool(o).Value})
		return true, nil
	case "f-setpipe-sz":
		n, err := requiredInt(o, 1)
		if err != nil {
			return true, err
		}
		appendAction(FileAction{Kind: FileActionPipeSize, Value: n})
		return true, nil
	case "fs-secrm", "fs-unrm", "fs-compr", "fs-sync", "fs-immutable", "fs-append", "fs-nodump", "fs-noatime", "fs-journal-data", "fs-notail", "fs-dirsync", "fs-topdir":
		enabled, err := optionalBool(o)
		if err != nil {
			return true, err
		}
		appendAction(FileAction{Kind: FileActionFSFlag, Enabled: enabled.Value, Text: name})
		return true, nil
	case "ioctl-void", "ioctl-int", "ioctl-intp", "ioctl-bin", "ioctl-string":
		action, err := decodeIoctl(o)
		if err != nil {
			return true, err
		}
		a.File.Actions = append(a.File.Actions, action)
		return true, nil
	case "umask":
		mode, err := fileMode(o, 0o777)
		if err != nil {
			return true, err
		}
		a.File.Umask = OptionalUint32{Set: true, Value: mode}
		return true, nil
	case "unlink":
		appendAction(FileAction{Kind: FileActionUnlink, Enabled: activeBool(o).Value})
		return true, nil
	case "unlink-early", "unlink-late", "unlink-close":
		v := activeBool(o)
		switch name {
		case "unlink-early":
			a.File.UnlinkEarly = v
		case "unlink-late":
			a.File.UnlinkLate = v
		default:
			a.File.UnlinkClose = v
		}
		return true, nil
	case "pipes", "pty", "ptmx", "openpty", "stderr", "setsid", "dash":
		v := activeBool(o)
		switch name {
		case "pipes":
			a.Process.Pipes = v
		case "stderr":
			a.Process.Stderr = v
		case "setsid":
			a.Process.SetSID = v
		case "dash":
			a.Process.Dash = v
		default:
			a.Process.PTY = v
		}
		return true, nil
	case "setpgid":
		n, err := signedOptionalInt(o)
		if err != nil {
			return true, err
		}
		a.Process.SetPGID = OptionalInt{Set: true, Value: n}
		return true, nil
	case "fdin", "fdout":
		n, set, err := processFD(o)
		if err != nil {
			return true, err
		}
		fd := OptionalInt{Set: set, Value: n}
		if name == "fdin" {
			a.Process.FDIn = fd
		} else {
			a.Process.FDOut = fd
		}
		return true, nil
	case "shell":
		a.Process.Shell = OptionalString{Set: true, Value: optionText(o)}
		return true, nil
	case "chdir":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		a.Process.Chdir = OptionalString{Set: true, Value: value}
		return true, nil
	case "sighup", "sigint", "sigquit":
		if o.Has {
			return true, fmt.Errorf("%s: no value permitted", o.OriginalSpelling())
		}
		var sig ParentSignal
		switch name {
		case "sighup":
			sig = ParentSignalHUP
		case "sigint":
			sig = ParentSignalINT
		default:
			sig = ParentSignalQUIT
		}
		a.Process.ParentSignals = append(a.Process.ParentSignals, sig)
		return true, nil
	case "lockfile", "waitlock":
		if a.File.LockSet {
			return true, errors.New("only one use of options lockfile and waitlock allowed")
		}
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		a.File.LockSet, a.File.LockWait, a.File.LockPath = true, name == "waitlock", value
		return true, nil
	}
	return false, nil
}

func fileMode(o parse.Option, max uint32) (uint32, error) {
	value, err := requiredString(o)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(strings.TrimSpace(value), 8, 32)
	if err != nil || n > uint64(max) {
		return 0, fmt.Errorf("invalid %s %q", o.OriginalSpelling(), value)
	}
	return uint32(n), nil
}

func nonnegativeInt64(o parse.Option) (int64, error) {
	if !o.Has {
		return 0, fmt.Errorf("%s: invalid value %q", o.OriginalSpelling(), o.Value)
	}
	n, err := strconv.ParseInt(strings.TrimSpace(o.Value), 0, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s: invalid value %q", o.OriginalSpelling(), o.Value)
	}
	return n, nil
}

func seekOffset(o parse.Option) (int64, error) {
	if !o.Has {
		return 1, nil
	}
	n, err := strconv.ParseInt(strings.TrimSpace(o.Value), 0, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid value %q", o.OriginalSpelling(), o.Value)
	}
	return n, nil
}

func signedOptionalInt(o parse.Option) (int, error) {
	if !o.Has {
		return 1, nil
	}
	n, err := strconv.ParseInt(strings.TrimSpace(o.Value), 0, 64)
	if err != nil || n > int64(math.MaxInt) || n < int64(math.MinInt) {
		return 0, fmt.Errorf("%s: invalid value %q", o.OriginalSpelling(), o.Value)
	}
	return int(n), nil
}

func processFD(o parse.Option) (int, bool, error) {
	value := optionText(o)
	if value == "" {
		return 0, false, nil
	}
	n, err := strconv.ParseInt(strings.TrimSpace(value), 0, 64)
	if err != nil || n < 0 || n > 1<<16-1 {
		return 0, false, fmt.Errorf("%s: invalid file descriptor %q", o.OriginalSpelling(), value)
	}
	return int(n), true, nil
}

func decodeTerminal(a *Address, o parse.Option) (bool, error) {
	name := optionIdentity(o)
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
		a.Terminal.WaitSlave = activeBool(o)
		return true, nil
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
