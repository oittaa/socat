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
			{name: "setsockopt", desc: "raw setsockopt after connect (dalan value)", aliases: []string{"sockopt"}, validate: validateSockoptBin},
			{name: "setsockopt-int", desc: "raw setsockopt after connect (int value)", aliases: []string{"sockopt-int"}, validate: validateSockoptInt},
			{name: "setsockopt-bin", desc: "raw setsockopt after connect (binary value)", aliases: []string{"sockopt-bin"}, validate: validateSockoptBin},
			{name: "setsockopt-string", desc: "raw setsockopt after connect (string value)", aliases: []string{"sockopt-string"}, validate: validateSockoptString},
			{name: "setsockopt-listen", desc: "raw setsockopt before bind (dalan value)", aliases: []string{"sockopt-listen"}, validate: validateSockoptBin},
			{name: "setsockopt-socket", desc: "raw setsockopt after socket (dalan value)", aliases: []string{"sockopt-sock"}, validate: validateSockoptBin},
			{name: "setsockopt-connected", desc: "raw setsockopt after connect (dalan value)", aliases: []string{"sockopt-conn"}, validate: validateSockoptBin},
			{name: "so-timestamp", desc: "SO_TIMESTAMP ancillary", aliases: []string{"timestamp"}},
			{name: "ip-pktinfo", desc: "IP_PKTINFO", aliases: []string{"pktinfo"}},
			{name: "ip-recvttl", desc: "IP_RECVTTL", aliases: []string{"recvttl"}},
			{name: "ip-recvtos", desc: "IP_RECVTOS", aliases: []string{"recvtos"}},
			{name: "ip-recvopts", desc: "IP_RECVOPTS", aliases: []string{"recvopts"}},
			{name: "ip-ttl", desc: "IP_TTL", aliases: []string{"ttl", "ipttl"}, validate: validateInteger(-1)},
			{name: "ip-tos", desc: "IP_TOS", aliases: []string{"tos", "iptos"}, validate: validateInt64(false)},
			{name: "ip-options", desc: "IP_OPTIONS"},
			{name: "ipv6-recvpktinfo", desc: "IPV6_RECVPKTINFO", aliases: []string{"recvpktinfo"}},
			{name: "ipv6-recvhoplimit", desc: "IPV6_RECVHOPLIMIT", aliases: []string{"recvhoplimit"}},
			{name: "ipv6-recvtclass", desc: "IPV6_RECVTCLASS", aliases: []string{"recvtclass"}},
			{name: "ipv6-unicast-hops", desc: "IPV6_UNICAST_HOPS", aliases: []string{"unicast-hops"}, validate: validateInteger(-1)},
			{name: "ipv6-tclass", desc: "IPV6_TCLASS", aliases: []string{"tclass"}, validate: validateInt64(false)},
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
