//go:build !linux && !windows

package cli

import "github.com/oittaa/socat/internal/xio"

func hideOpt(name string) bool {
	if (name == "udplite-send-cscov" || name == "udplite-recv-cscov") && !xio.FeatureUDPLITE {
		return true
	}
	if name == "async" && !xio.FeatureFDAsync {
		return true
	}
	if (name == "flock" || name == "flock-nb" || name == "flock-sh" || name == "flock-sh-nb") && !xio.FeatureFlock {
		return true
	}
	if xio.LinuxExtFSFlagOption(name) {
		return true
	}
	switch name {
	case "o-noatime", "o-direct", "o-rsync", "o-largefile", "f-setpipe-sz", "bindtodevice",
		"ip-freebind", "freebind", "ipfreebind",
		"ip-transparent", "transparent",
		"ip-mtu-discover", "mtudiscover", "ipmtudiscover",
		"ipv6-mtu-discover", "mtudiscover6",
		"tcp-cork", "tcp-defer-accept", "tcp-linger2",
		"tcp-quickack", "tcp-syncnt", "tcp-window-clamp",
		"sctp-nodelay", "sctp-maxseg",
		"so-priority", "so-passcred", "so-no-check":
		return true
	default:
		return false
	}
}
