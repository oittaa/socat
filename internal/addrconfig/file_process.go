package addrconfig

import (
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

// OwnerRef is a numeric uid/gid or an account name. Names are resolved during
// preparation; apply uses the numeric id.
type OwnerRef struct {
	ID      int
	Numeric bool
	Name    string
}

// parseOwnerRef applies the user/group rule: a leading digit is strtoul, and
// any other spelling is an account name resolved before the address is opened.
func parseOwnerRef(value string) (OwnerRef, error) {
	n, numeric, err := parseDigitStrtoul(value, strconv.IntSize)
	if err != nil {
		return OwnerRef{}, err
	}
	if numeric {
		if n > uint64(math.MaxInt) {
			return OwnerRef{}, fmt.Errorf("invalid integer %q", value)
		}
		return OwnerRef{ID: int(n), Numeric: true, Name: value}, nil
	}
	return OwnerRef{Name: value}, nil
}

// Process holds EXEC/SYSTEM/SHELL choices. Commands stay positional.
type Process struct {
	Argv          []string
	Command       string
	HasCommand    bool // parameter present, including an empty command
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
	// doc/socat.yo: a missing value defaults to 1, not 0.
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
	value, err := requiredString(o)
	if err != nil {
		return 0, false, err
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
