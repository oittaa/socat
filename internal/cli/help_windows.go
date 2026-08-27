//go:build windows

package cli

func hideOpt(name string) bool {
	switch name {
	case "reuseport",
		"ip-add-membership", "ipv6-join-group",
		"add-membership", "ip-membership", "membership",
		"ipv6-add-membership", "join-group",
		"ip-multicast-if", "multicast-if",
		"ip-multicast-loop", "multicast-loop", "mcloop",
		"ip-multicast-ttl", "multicast-ttl",
		"ipv6-multicast-loop", "ipv6-mcloop", "mcloop6",
		"ip-add-source-membership", "source-membership", "add-source-membership",
		"ipv6-join-source-group", "ipv6-add-source-membership", "join-source-group",
		"ip-freebind", "freebind", "ipfreebind",
		"ip-transparent", "transparent",
		"so-timestamp", "ip-pktinfo", "ip-recvttl", "ip-recvtos", "ip-recvopts",
		"ip-options",
		"ipv6-recvpktinfo", "ipv6-recvhoplimit", "ipv6-recvtclass",
		"ipv6-unicast-hops", "ipv6-tclass",
		"nonblock", "o-noatime", "o-direct", "fs-noatime", "f-setpipe-sz", "umask", "user", "group",
		"perm-early", "user-early", "group-early",
		"setlk", "setlkw", "setlk-rd", "setlkw-rd",
		"pipes", "pty", "setsid", "stderr", "fdin", "fdout", "shell", "shut-none",
		"bindtodevice":
		return true
	default:
		return false
	}
}
