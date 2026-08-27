//go:build windows

package cli

func hideOpt(name string) bool {
	switch name {
	case "reuseport",
		"ip-add-membership", "ipv6-join-group",
		"add-membership", "ip-membership", "membership",
		"ipv6-add-membership", "join-group",
		"so-timestamp", "ip-pktinfo", "ip-recvttl", "ip-recvtos", "ip-recvopts",
		"ip-options",
		"ipv6-recvpktinfo", "ipv6-recvhoplimit", "ipv6-recvtclass",
		"ipv6-unicast-hops", "ipv6-tclass",
		"nonblock", "o-noatime", "o-direct", "fs-noatime", "f-setpipe-sz", "umask", "user", "group",
		"perm-early", "user-early", "group-early",
		"o-sync", "o-dsync", "o-rsync", "o-noctty", "o-nofollow", "o-directory", "o-largefile",
		"async", "perm-late", "user-late", "group-late",
		"setlk", "setlkw", "setlk-rd", "setlkw-rd",
		"flock", "flock-nb", "flock-sh", "flock-sh-nb",
		"pipes", "pty", "setsid", "stderr", "fdin", "fdout", "shell", "shut-none",
		"bindtodevice":
		return true
	default:
		return false
	}
}
