//go:build windows

package fileopen

// Windows has no O_SYNC / O_ASYNC / O_NOCTTY family. Reject enabled flags.
var openFlagTable = []openFlag{
	{name: "o-direct", supported: false},
	{name: "o-sync", supported: false},
	{name: "o-dsync", supported: false},
	{name: "o-rsync", supported: false},
	{name: "o-noctty", supported: false},
	{name: "o-nofollow", supported: false},
	{name: "o-directory", supported: false},
	{name: "o-largefile", supported: false},
	{name: "async", supported: false},
}
