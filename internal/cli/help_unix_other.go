//go:build !linux && !windows

package cli

import "github.com/oittaa/socat/internal/xio"

func hideOpt(name string) bool {
	if name == "async" && !xio.FeatureFDAsync {
		return true
	}
	if (name == "flock" || name == "flock-nb" || name == "flock-sh" || name == "flock-sh-nb") && !xio.FeatureFlock {
		return true
	}
	switch name {
	case "o-noatime", "o-direct", "o-rsync", "o-largefile", "fs-noatime", "f-setpipe-sz", "bindtodevice":
		return true
	default:
		return false
	}
}
