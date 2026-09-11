//go:build linux

package fileopen

import (
	"github.com/oittaa/socat/internal/addrconfig"
	"golang.org/x/sys/unix"
)

// Linux glibc open(2) bits. O_RSYNC equals O_SYNC; O_LARGEFILE is 0 on
// 64-bit but the option is still advertised and accepted (-hhh).
var openFlagTable = []openFlag{
	{id: addrconfig.OpenFlagDirect, bit: unix.O_DIRECT, supported: true},
	{id: addrconfig.OpenFlagSync, bit: unix.O_SYNC, supported: true},
	{id: addrconfig.OpenFlagDSync, bit: unix.O_DSYNC, supported: true},
	{id: addrconfig.OpenFlagRSync, bit: unix.O_RSYNC, supported: true},
	{id: addrconfig.OpenFlagNoCTTY, bit: unix.O_NOCTTY, supported: true},
	{id: addrconfig.OpenFlagNoFollow, bit: unix.O_NOFOLLOW, supported: true},
	{id: addrconfig.OpenFlagDirectory, bit: unix.O_DIRECTORY, supported: true},
	{id: addrconfig.OpenFlagLargeFile, bit: unix.O_LARGEFILE, supported: true},
	{id: addrconfig.OpenFlagAsync, bit: unix.O_ASYNC, supported: true},
}
