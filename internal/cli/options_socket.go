package cli

import "github.com/oittaa/socat/internal/xio"

// Socket, IP, and TCP options.
func socketOptionGroups() []helpOptGroup {
	return []helpOptGroup{
		{"Sockets", []helpOpt{
			{name: "nodelay", desc: "TCP_NODELAY", aliases: []string{"tcp-nodelay"}, addressTypes: tcpStreamAddressTypes()},
			{name: "keepalive", desc: "SO_KEEPALIVE", aliases: []string{"so-keepalive"}, addressTypes: tcpStreamAddressTypes()},
			{name: "keepidle", desc: "TCP_KEEPIDLE idle time (requires keepalive)", aliases: []string{"so-keepidle", "tcp-keepidle"}, addressTypes: tcpStreamAddressTypes(), validate: validateDurationOption},
			{name: "keepintvl", desc: "TCP_KEEPINTVL probe interval", aliases: []string{"so-keepintvl", "tcp-keepintvl"}, addressTypes: tcpStreamAddressTypes(), validate: validateDurationOption},
			{name: "keepcnt", desc: "TCP_KEEPCNT probe count", aliases: []string{"so-keepcnt", "tcp-keepcnt"}, addressTypes: tcpStreamAddressTypes(), validate: validateInteger(1)},
			{name: "broadcast", desc: "SO_BROADCAST"},
			{name: "ip-add-membership", desc: "IPv4 multicast join"},
			{name: "ipv6-join-group", desc: "IPv6 multicast join"},
			{name: "setsockopt", desc: "raw setsockopt (level, opt, value)", validate: validateSockopt},
			{name: "setsockopt-listen", desc: "raw setsockopt before bind (level, opt, value)", aliases: []string{"sockopt-listen"}, validate: validateSockopt},
			{name: "so-timestamp", desc: "SO_TIMESTAMP ancillary", aliases: []string{"timestamp"}, implementationGroups: xio.IPAncillaryImplementationGroups("so-timestamp")},
			{name: "ip-pktinfo", desc: "IP_PKTINFO", aliases: []string{"pktinfo"}, implementationGroups: xio.IPAncillaryImplementationGroups("ip-pktinfo")},
			{name: "ip-recvttl", desc: "IP_RECVTTL", aliases: []string{"recvttl"}, implementationGroups: xio.IPAncillaryImplementationGroups("ip-recvttl")},
			{name: "ip-recvtos", desc: "IP_RECVTOS", aliases: []string{"recvtos"}, implementationGroups: xio.IPAncillaryImplementationGroups("ip-recvtos")},
			{name: "ip-recvopts", desc: "IP_RECVOPTS", aliases: []string{"recvopts"}, implementationGroups: xio.IPAncillaryImplementationGroups("ip-recvopts")},
			{name: "ip-ttl", desc: "IP_TTL", aliases: []string{"ttl", "ipttl"}, implementationGroups: xio.IPAncillaryImplementationGroups("ip-ttl"), validate: validateInteger(-1)},
			{name: "ip-tos", desc: "IP_TOS", aliases: []string{"tos", "iptos"}, implementationGroups: xio.IPAncillaryImplementationGroups("ip-tos"), validate: validateInt64(false)},
			{name: "ip-options", desc: "IP_OPTIONS", implementationGroups: xio.IPAncillaryImplementationGroups("ip-options"), validate: validateRequiredString},
			{name: "ipv6-recvpktinfo", desc: "IPV6_RECVPKTINFO", aliases: []string{"recvpktinfo"}, implementationGroups: xio.IPAncillaryImplementationGroups("ipv6-recvpktinfo")},
			{name: "ipv6-recvhoplimit", desc: "IPV6_RECVHOPLIMIT", aliases: []string{"recvhoplimit"}, implementationGroups: xio.IPAncillaryImplementationGroups("ipv6-recvhoplimit")},
			{name: "ipv6-recvtclass", desc: "IPV6_RECVTCLASS", aliases: []string{"recvtclass"}, implementationGroups: xio.IPAncillaryImplementationGroups("ipv6-recvtclass")},
			{name: "ipv6-unicast-hops", desc: "IPV6_UNICAST_HOPS", aliases: []string{"unicast-hops"}, implementationGroups: xio.IPAncillaryImplementationGroups("ipv6-unicast-hops"), validate: validateInteger(-1)},
			{name: "ipv6-tclass", desc: "IPV6_TCLASS", aliases: []string{"tclass"}, implementationGroups: xio.IPAncillaryImplementationGroups("ipv6-tclass"), validate: validateInt64(false)},
			{name: "rcvtimeo", desc: "per-operation socket receive timeout; retry after expiration", aliases: []string{"so-rcvtimeo"}, addressTypes: socketTimeoutAddressTypes(), validate: validateDurationOption},
			{name: "sndtimeo", desc: "per-operation socket send timeout; retry after expiration", aliases: []string{"so-sndtimeo"}, addressTypes: socketTimeoutAddressTypes(), validate: validateDurationOption},
			{name: "so-linger", desc: "SO_LINGER timeout in seconds", aliases: []string{"linger"}, addressTypes: socketTimeoutAddressTypes(), validate: validateInteger(0)},
			{name: "sndbuf", desc: "SO_SNDBUF size in bytes", aliases: []string{"so-sndbuf"}, addressTypes: socketTimeoutAddressTypes(), validate: validateInteger(0)},
			{name: "rcvbuf", desc: "SO_RCVBUF size in bytes", aliases: []string{"so-rcvbuf"}, addressTypes: socketTimeoutAddressTypes(), validate: validateInteger(0)},
			{name: "sndbuf-late", desc: "SO_SNDBUF after connect, accept, or bind (raw socket, before TLS/PROXY/QUIC wrapping)", aliases: []string{"so-sndbuf-late"}, addressTypes: socketTimeoutAddressTypes(), validate: validateInteger(0)},
			{name: "rcvbuf-late", desc: "SO_RCVBUF after connect, accept, or bind (raw socket, before TLS/PROXY/QUIC wrapping)", aliases: []string{"so-rcvbuf-late"}, addressTypes: socketTimeoutAddressTypes(), validate: validateInteger(0)},
			{name: "bindtodevice", desc: "SO_BINDTODEVICE interface name", aliases: []string{"so-bindtodevice", "if", "interface"}, addressTypes: socketTimeoutAddressTypes(), validate: validateRequiredString},
			{name: "so-protocol", desc: "socket() protocol number", aliases: []string{"so-prototype", "prototype"}, implementationGroups: []string{xio.GroupVSOCK}, validate: validateInteger(-1)},
		}},
	}
}
