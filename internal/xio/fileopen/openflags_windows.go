//go:build windows

package fileopen

import "github.com/oittaa/socat/internal/addrconfig"

// Windows has no O_SYNC / O_ASYNC / O_NOCTTY family. Reject enabled flags.
var openFlagTable = []openFlag{
	{id: addrconfig.OpenFlagDirect, supported: false},
	{id: addrconfig.OpenFlagSync, supported: false},
	{id: addrconfig.OpenFlagDSync, supported: false},
	{id: addrconfig.OpenFlagRSync, supported: false},
	{id: addrconfig.OpenFlagNoCTTY, supported: false},
	{id: addrconfig.OpenFlagNoFollow, supported: false},
	{id: addrconfig.OpenFlagDirectory, supported: false},
	{id: addrconfig.OpenFlagLargeFile, supported: false},
	{id: addrconfig.OpenFlagAsync, supported: false},
}
