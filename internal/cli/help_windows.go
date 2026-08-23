//go:build windows

package cli

func hideOpt(name string) bool {
	switch name {
	case "reuseport",
		"ip-add-membership", "ipv6-join-group",
		"so-timestamp", "ip-pktinfo", "ip-recvttl", "ip-recvtos", "ip-recvopts",
		"ip-ttl", "ip-tos", "ip-options",
		"ipv6-recvpktinfo", "ipv6-recvhoplimit", "ipv6-recvtclass",
		"ipv6-unicast-hops", "ipv6-tclass",
		"nonblock", "o-noatime", "f-setpipe-sz", "umask", "user", "group",
		"setlk", "setlkw", "setlk-rd", "setlkw-rd",
		"pipes", "pty", "setsid", "stderr", "fdin", "fdout", "shell", "shut-none":
		return true
	default:
		return false
	}
}
