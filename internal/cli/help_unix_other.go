//go:build !linux && !windows

package cli

func hideOpt(name string) bool {
	switch name {
	case "o-noatime", "o-direct", "fs-noatime", "f-setpipe-sz", "bindtodevice":
		return true
	default:
		return false
	}
}
