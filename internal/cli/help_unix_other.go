//go:build !linux && !windows

package cli

func hideOpt(name string) bool {
	switch name {
	case "o-noatime", "o-direct", "fs-noatime", "f-setpipe-sz", "bindtodevice",
		"ip-freebind", "freebind", "ipfreebind",
		"ip-transparent", "transparent",
		"ip-mtu-discover", "mtudiscover", "ipmtudiscover",
		"ipv6-mtu-discover", "mtudiscover6":
		return true
	default:
		return false
	}
}
