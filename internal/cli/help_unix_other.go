//go:build !linux && !windows

package cli

func hideOpt(name string) bool {
	switch name {
	case "o-noatime", "f-setpipe-sz":
		return true
	default:
		return false
	}
}
