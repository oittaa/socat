//go:build darwin

package fileopen

import (
	"github.com/oittaa/socat/internal/addrconfig"
	"golang.org/x/sys/unix"
)

// macOS does not expose O_DIRECT, O_RSYNC, or O_LARGEFILE. Reject them rather than no-op.
var openFlagTable = []openFlag{
	{id: addrconfig.OpenFlagDirect, bit: 0, supported: false},
	{id: addrconfig.OpenFlagSync, bit: unix.O_SYNC, supported: true},
	{id: addrconfig.OpenFlagDSync, bit: oDSyncFlag, supported: oDSyncSupported},
	{id: addrconfig.OpenFlagRSync, bit: 0, supported: false},
	{id: addrconfig.OpenFlagNoCTTY, bit: unix.O_NOCTTY, supported: true},
	{id: addrconfig.OpenFlagNoFollow, bit: unix.O_NOFOLLOW, supported: true},
	{id: addrconfig.OpenFlagDirectory, bit: unix.O_DIRECTORY, supported: true},
	{id: addrconfig.OpenFlagLargeFile, bit: 0, supported: false},
	{id: addrconfig.OpenFlagAsync, bit: oAsyncFlag, supported: oAsyncSupported},
}
