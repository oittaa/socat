package xio

import (
	"fmt"
	"os"
	"strconv"

	"github.com/oittaa/socat/internal/parse"
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

// ParseUnixMode returns perm=/mode= as 07777 bits, else def.
func ParseUnixMode(s parse.Spec, def uint32) (uint32, error) {
	m, ok, err := explicitUnixMode(s)
	if err != nil {
		return 0, err
	}
	if ok {
		return m, nil
	}
	return def, nil
}

func explicitUnixMode(s parse.Spec) (uint32, bool, error) {
	var name, v string
	for i := len(s.Options) - 1; i >= 0; i-- {
		n := parse.CanonicalOptionName(s.Options[i].Name)
		if n == "perm" || n == "mode" {
			name = n
			v = s.Options[i].Value
			break
		}
	}
	if name == "" || v == "" {
		return 0, false, nil
	}
	m, err := strconv.ParseUint(v, 8, 32)
	if err != nil || m > 0o7777 {
		return 0, false, fmt.Errorf("invalid %s %q", name, v)
	}
	return uint32(m), true, nil
}
