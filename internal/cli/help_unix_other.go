//go:build !linux && !windows

package cli

func hideOpt(name string) bool {
	switch name {
	case "o-noatime", "o-direct", "fs-noatime", "f-setpipe-sz", "bindtodevice",
		"tcp-cork", "tcp-defer-accept", "tcp-linger2",
		"tcp-quickack", "tcp-syncnt", "tcp-window-clamp":
		return true
	default:
		return false
	}
}
