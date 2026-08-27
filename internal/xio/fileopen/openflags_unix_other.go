//go:build unix && !linux

package fileopen

import "golang.org/x/sys/unix"

// Darwin and other non-Linux Unix: O_DIRECT / O_RSYNC / O_LARGEFILE are not
// public glibc Linux flags here. Reject them rather than no-op.
var openFlagTable = []openFlag{
	{name: "o-direct", bit: 0, supported: false},
	{name: "o-sync", bit: unix.O_SYNC, supported: true},
	{name: "o-dsync", bit: oDSyncFlag, supported: oDSyncSupported},
	{name: "o-rsync", bit: 0, supported: false},
	{name: "o-noctty", bit: unix.O_NOCTTY, supported: true},
	{name: "o-nofollow", bit: unix.O_NOFOLLOW, supported: true},
	{name: "o-directory", bit: unix.O_DIRECTORY, supported: true},
	{name: "o-largefile", bit: 0, supported: false},
	{name: "async", bit: oAsyncFlag, supported: oAsyncSupported},
}
