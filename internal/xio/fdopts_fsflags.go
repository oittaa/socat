package xio

import (
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// linux/fs.h FS_*_FL masks used by classic xio-fs.c OFUNC_IOCTL_MASK_LONG
// (https://repo.or.cz/socat.git tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same xio-fs.c tree).
// golang.org/x/sys/unix exports FS_IOC_GETFLAGS / FS_IOC_SETFLAGS but not
// these flag bits.
const (
	fsSecrmFL       = 0x00000001
	fsUnrmFL        = 0x00000002
	fsComprFL       = 0x00000004
	fsSyncFL        = 0x00000008
	fsImmutableFL   = 0x00000010
	fsAppendFL      = 0x00000020
	fsNodumpFL      = 0x00000040
	fsNoatimeFL     = 0x00000080
	fsJournalDataFL = 0x00004000
	fsNotailFL      = 0x00008000
	fsDirsyncFL     = 0x00010000
	fsTopdirFL      = 0x00020000
)

// linuxExtFSFlagMasks maps canonical GROUP_REG fs-* names to FS_*_FL.
// Short nicknames append/sync/noatime are not keys: classic optionnames[]
// maps those spellings to O_APPEND / O_SYNC / O_NOATIME.
var linuxExtFSFlagMasks = map[string]int{
	"fs-secrm":        fsSecrmFL,
	"fs-unrm":         fsUnrmFL,
	"fs-compr":        fsComprFL,
	"fs-sync":         fsSyncFL,
	"fs-immutable":    fsImmutableFL,
	"fs-append":       fsAppendFL,
	"fs-nodump":       fsNodumpFL,
	"fs-noatime":      fsNoatimeFL,
	"fs-journal-data": fsJournalDataFL,
	"fs-notail":       fsNotailFL,
	"fs-dirsync":      fsDirsyncFL,
	"fs-topdir":       fsTopdirFL,
}

type linuxExtFSFlagOp struct {
	name   string
	mask   int
	enable bool
}

// LinuxExtFSFlagOption reports whether name is a canonical Linux ext
// filesystem ioctl flag (fs-append, fs-nodump, …). Used to hide these
// options on Darwin/Windows the same way as fs-noatime.
func LinuxExtFSFlagOption(name string) bool {
	_, ok := linuxExtFSFlagMasks[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func linuxExtFSFlagOps(s parse.Spec) []linuxExtFSFlagOp {
	var out []linuxExtFSFlagOp
	for _, o := range s.Options {
		canon := parse.CanonicalOptionName(o.Name)
		mask, ok := linuxExtFSFlagMasks[canon]
		if !ok {
			continue
		}
		out = append(out, linuxExtFSFlagOp{name: canon, mask: mask, enable: optionEnabled(o)})
	}
	return out
}

// applyFSFlagMask implements classic applyopt_ioctl_mask_long's in-memory
// step: val &= ~mask, then if bool val |= mask. Unrelated bits are kept.
func applyFSFlagMask(val, mask int, enable bool) int {
	val &^= mask
	if enable {
		val |= mask
	}
	return val
}
