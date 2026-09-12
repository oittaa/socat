package xio

import (
	"os"
)

// UnixModeToFileMode converts Unix 07777 mode bits to os.FileMode.
// os.FileMode(04755) drops setuid/setgid/sticky; those live in dedicated Mode*
// bits and must be set explicitly so Chmod/OpenFile can round-trip them.
func UnixModeToFileMode(m uint32) os.FileMode {
	mode := os.FileMode(m & 0o777)
	if m&0o4000 != 0 {
		mode |= os.ModeSetuid
	}
	if m&0o2000 != 0 {
		mode |= os.ModeSetgid
	}
	if m&0o1000 != 0 {
		mode |= os.ModeSticky
	}
	return mode
}

// FileModeToUnix converts os.FileMode back to Unix 07777 bits.
func FileModeToUnix(mode os.FileMode) uint32 {
	m := uint32(mode.Perm())
	if mode&os.ModeSetuid != 0 {
		m |= 0o4000
	}
	if mode&os.ModeSetgid != 0 {
		m |= 0o2000
	}
	if mode&os.ModeSticky != 0 {
		m |= 0o1000
	}
	return m
}
