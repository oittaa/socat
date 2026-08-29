//go:build windows

package cli

import "github.com/oittaa/socat/internal/xio"

func hideOpt(name string) bool {
	if hideDarwinOnlyIPRecv(name, "windows") {
		return true
	}
	if hideLinuxOnlyRemainingIPv4(name, "windows") {
		return true
	}
	if xio.LinuxExtFSFlagOption(name) {
		return true
	}
	if xio.GenericIoctlOption(name) {
		return true
	}
	switch name {
	case "reuseport",
		"ip-add-membership", "ipv6-join-group",
		"add-membership", "ip-membership", "membership",
		"ipv6-add-membership", "join-group",
		"ip-multicast-if", "multicast-if",
		"ip-multicast-loop", "multicast-loop", "mcloop", "ipmulticastloop", "multicastloop",
		"ip-multicast-ttl", "multicast-ttl", "ipmulticastttl", "multicastttl",
		"ipv6-multicast-loop", "ipv6-mcloop", "mcloop6",
		"ip-add-source-membership", "source-membership", "add-source-membership",
		"ipv6-join-source-group", "ipv6-add-source-membership", "join-source-group",
		"ip-freebind", "freebind", "ipfreebind",
		"ip-transparent", "transparent",
		"ip-mtu-discover", "mtudiscover", "ipmtudiscover",
		"ipv6-mtu-discover", "mtudiscover6",
		"so-timestamp", "ip-pktinfo", "ip-recvttl", "ip-recvtos", "ip-recvopts",
		"ip-options", "ip-hdrincl", "hdrincl", "iphdrincl",
		"ipv6-recvpktinfo", "ipv6-recvhoplimit", "ipv6-recvtclass",
		"ipv6-recvdstopts", "recvdstopts",
		"ipv6-recvhopopts", "recvhopopts",
		"ipv6-recvrthdr", "recvrthdr",
		"ipv6-recvpathmtu",
		"ipv6-unicast-hops", "ipv6-tclass",
		"nonblock", "o-noatime", "o-direct", "f-setpipe-sz", "umask", "user", "group",
		"perm-early", "user-early", "group-early",
		"o-sync", "o-dsync", "o-rsync", "o-noctty", "o-nofollow", "o-directory", "o-largefile",
		"async", "perm-late", "user-late", "group-late",
		"setlk", "setlkw", "setlk-rd", "setlkw-rd",
		"flock", "flock-nb", "flock-sh", "flock-sh-nb",
		"cloexec",
		"pipes", "pty", "setsid", "dash", "setpgid", "sighup", "sigint", "sigquit", "stderr", "fdin", "fdout", "shell", "shut-none",
		"bindtodevice",
		"tcp-cork", "tcp-defer-accept", "tcp-linger2", "tcp-maxseg",
		"tcp-maxseg-late", "tcp-quickack", "tcp-syncnt", "tcp-window-clamp",
		"nopush", "noopt", "tcp-nopush", "tcp-noopt",
		"sctp-nodelay", "sctp-maxseg",
		"so-rcvlowat", "so-sndlowat",
		"so-priority", "so-passcred", "so-no-check",
		"so-detach-filter",
		"fiosetown", "siocspgrp",
		"unix-tightsocklen", "tightsocklen":
		return true
	default:
		return false
	}
}
