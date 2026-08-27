//go:build linux

package fileopen

import "golang.org/x/sys/unix"

// Linux glibc open(2) bits. O_RSYNC equals O_SYNC; O_LARGEFILE is 0 on 64-bit
// but the option is still advertised and accepted (classic -hhh).
var openFlagTable = []openFlag{
	{name: "o-direct", bit: unix.O_DIRECT, supported: true},
	{name: "o-sync", bit: unix.O_SYNC, supported: true},
	{name: "o-dsync", bit: unix.O_DSYNC, supported: true},
	{name: "o-rsync", bit: unix.O_RSYNC, supported: true},
	{name: "o-noctty", bit: unix.O_NOCTTY, supported: true},
	{name: "o-nofollow", bit: unix.O_NOFOLLOW, supported: true},
	{name: "o-directory", bit: unix.O_DIRECTORY, supported: true},
	{name: "o-largefile", bit: unix.O_LARGEFILE, supported: true},
	{name: "async", bit: unix.O_ASYNC, supported: true},
}
