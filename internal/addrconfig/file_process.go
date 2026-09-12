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
	Path        string
	Access      FileAccess
	Create      OptionalBool
	Exclusive   bool
	AppendSet   bool
	Append      bool
	Truncate    bool
	Nonblock    bool
	FD          int
	FDSet       bool
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

// OpenFlag is the dispatch identity of an open(2) bit option.
type OpenFlag uint8

const (
	OpenFlagNone OpenFlag = iota
	OpenFlagDirect
	OpenFlagSync
	OpenFlagDSync
	OpenFlagRSync
	OpenFlagNoCTTY
	OpenFlagNoFollow
	OpenFlagDirectory
	OpenFlagLargeFile
	OpenFlagAsync
)

// FSFlag is the dispatch identity of a Linux ext FS_IOC_* bit.
type FSFlag uint8

const (
	FSFlagNone FSFlag = iota
	FSFlagSecrm
	FSFlagUnrm
	FSFlagCompr
	FSFlagSync
	FSFlagImmutable
	FSFlagAppend
	FSFlagNodump
	FSFlagNoatime
	FSFlagJournalData
	FSFlagNotail
	FSFlagDirsync
	FSFlagTopdir
)

// IoctlForm is the decoded ioctl value shape.
type IoctlForm uint8

const (
	IoctlNone IoctlForm = iota
	IoctlVoid
	IoctlInt
	IoctlIntp
	IoctlBin
	IoctlString
)

// FileAction is one filesystem operation in source order.
type FileAction struct {
	Kind    FileActionKind
	Name    string
	Enabled bool
	Mode    uint32
	Offset  int64
	Value   int
	Text    string
	Flag    OpenFlag
	FS      FSFlag
	Ioctl   IoctlForm
	Request uint32
	Bytes   []byte
	Owner   OwnerRef
}

// OwnerRef is a numeric uid/gid or an account name resolved at apply time.
type OwnerRef struct {
	ID      int
	Numeric bool
	Name    string
}

func parseOwnerRef(value string) OwnerRef {
	if n, err := strconv.Atoi(value); err == nil {
		return OwnerRef{ID: n, Numeric: true, Name: value}
	}
	return OwnerRef{Name: value}
}

// Process holds EXEC/SYSTEM/SHELL choices. Commands stay positional.
type Process struct {
	Argv          []string
	Command       string
	HasCommand    bool
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

func decodeFileProcess(a *Address, o parse.Option, name string) (bool, error) {
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
		return true, setActive(&a.File.Create, o)
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
		appendAction(FileAction{Kind: FileActionOpenFlag, Flag: openFlagID(name), Name: name, Enabled: activeBool(o).Value})
		return true, nil
	case "async":
		enabled := activeBool(o).Value
		appendAction(FileAction{Kind: FileActionAsync, Flag: OpenFlagAsync, Name: name, Enabled: enabled})
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
		appendAction(FileAction{Kind: kind, Owner: parseOwnerRef(value)})
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
		appendAction(FileAction{Kind: FileActionFSFlag, Enabled: enabled.Value, FS: fsFlagID(name), Name: name})
		return true, nil
	case "ioctl-void", "ioctl-int", "ioctl-intp", "ioctl-bin", "ioctl-string":
		action, err := decodeIoctl(o, name)
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

func openFlagID(name string) OpenFlag { return openFlagByName[name] }

var openFlagByName = map[string]OpenFlag{
	"o-direct":    OpenFlagDirect,
	"o-sync":      OpenFlagSync,
	"o-dsync":     OpenFlagDSync,
	"o-rsync":     OpenFlagRSync,
	"o-noctty":    OpenFlagNoCTTY,
	"o-nofollow":  OpenFlagNoFollow,
	"o-directory": OpenFlagDirectory,
	"o-largefile": OpenFlagLargeFile,
	"async":       OpenFlagAsync,
}

func fsFlagID(name string) FSFlag { return fsFlagByName[name] }

var fsFlagByName = map[string]FSFlag{
	"fs-secrm":        FSFlagSecrm,
	"fs-unrm":         FSFlagUnrm,
	"fs-compr":        FSFlagCompr,
	"fs-sync":         FSFlagSync,
	"fs-immutable":    FSFlagImmutable,
	"fs-append":       FSFlagAppend,
	"fs-nodump":       FSFlagNodump,
	"fs-noatime":      FSFlagNoatime,
	"fs-journal-data": FSFlagJournalData,
	"fs-notail":       FSFlagNotail,
	"fs-dirsync":      FSFlagDirsync,
	"fs-topdir":       FSFlagTopdir,
}
