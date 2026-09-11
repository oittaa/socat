package xio

import (
	"github.com/oittaa/socat/internal/addrconfig"
)

// linux/fs.h FS_*_FL masks. golang.org/x/sys/unix exports FS_IOC_GETFLAGS /
// FS_IOC_SETFLAGS but not these flag bits.
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

// linuxExtFSFlagMasks maps typed fs-* flags to FS_*_FL. Short nicknames
// append/sync/noatime are not keys: those spellings map to O_APPEND / O_SYNC /
// O_NOATIME.
var linuxExtFSFlagMasks = map[addrconfig.FSFlag]int{
	addrconfig.FSFlagSecrm:       fsSecrmFL,
	addrconfig.FSFlagUnrm:        fsUnrmFL,
	addrconfig.FSFlagCompr:       fsComprFL,
	addrconfig.FSFlagSync:        fsSyncFL,
	addrconfig.FSFlagImmutable:   fsImmutableFL,
	addrconfig.FSFlagAppend:      fsAppendFL,
	addrconfig.FSFlagNodump:      fsNodumpFL,
	addrconfig.FSFlagNoatime:     fsNoatimeFL,
	addrconfig.FSFlagJournalData: fsJournalDataFL,
	addrconfig.FSFlagNotail:      fsNotailFL,
	addrconfig.FSFlagDirsync:     fsDirsyncFL,
	addrconfig.FSFlagTopdir:      fsTopdirFL,
}

// applyFSFlagMask: val &= ~mask, then |= mask when enable. Unrelated bits
// are kept.
func applyFSFlagMask(val, mask int, enable bool) int {
	val &^= mask
	if enable {
		val |= mask
	}
	return val
}
