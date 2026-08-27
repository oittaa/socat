package classiccatalog

// ParserAddressShorthands are classic addressnames[] aliases implemented in
// the parser rather than the address registry. "-" → STDIO is already
// handled in parse.ParseSpec.
var ParserAddressShorthands = map[string]string{
	"-": "STDIO",
}

// UnsupportedAddressNames are canonical families this port does not
// implement, plus every classic alias of those families. Keep them out of
// the supported-alias backlog (PR C) even when the alias spelling looks like
// a TCP/UDP name.
//
// Classic baseline: tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba;
// official master af5388c898c7bb60997935aee93c223deba60c4a.
var UnsupportedAddressNames = map[string]string{
	"READLINE": "GNU readline is not implemented (#undef WITH_READLINE)",

	"DCCP":          "DCCP is not implemented (#undef WITH_DCCP)",
	"DCCP-CONNECT":  "DCCP is not implemented",
	"DCCP-L":        "DCCP is not implemented",
	"DCCP-LISTEN":   "DCCP is not implemented",
	"DCCP4":         "DCCP is not implemented",
	"DCCP4-CONNECT": "DCCP is not implemented",
	"DCCP4-L":       "DCCP is not implemented",
	"DCCP4-LISTEN":  "DCCP is not implemented",
	"DCCP6":         "DCCP is not implemented",
	"DCCP6-CONNECT": "DCCP is not implemented",
	"DCCP6-L":       "DCCP is not implemented",
	"DCCP6-LISTEN":  "DCCP is not implemented",

	"DTLS":                 "DTLS is not implemented (Go crypto/tls is stream TLS only)",
	"DTLS-C":               "DTLS is not implemented",
	"DTLS-CLIENT":          "DTLS is not implemented",
	"DTLS-CONNECT":         "DTLS is not implemented",
	"DTLS-L":               "DTLS is not implemented",
	"DTLS-LISTEN":          "DTLS is not implemented",
	"DTLS-SERVER":          "DTLS is not implemented",
	"OPENSSL-DTLS-CLIENT":  "DTLS is not implemented",
	"OPENSSL-DTLS-CONNECT": "DTLS is not implemented",
	"OPENSSL-DTLS-LISTEN":  "DTLS is not implemented",
	"OPENSSL-DTLS-SERVER":  "DTLS is not implemented",
}

// ExpectedMissingCanonicalAddresses are classic canonical address types whose
// Go opener is not registered. ACCEPT-FD is PR F (Unix). UDPLITE is a later
// Linux-only family; net.UDPConn cannot be relabeled as IPPROTO_UDPLITE.
var ExpectedMissingCanonicalAddresses = map[string]Gap{
	"ACCEPT-FD": {Reason: "consume an already-accepted stream socket (PR F)", Platforms: PlatUnix},

	"UDPLITE-CONNECT":   {Reason: "IPPROTO_UDPLITE connect (later Linux-only PR)", Platforms: PlatLinux},
	"UDPLITE-DATAGRAM":  {Reason: "IPPROTO_UDPLITE datagram", Platforms: PlatLinux},
	"UDPLITE-LISTEN":    {Reason: "IPPROTO_UDPLITE listen", Platforms: PlatLinux},
	"UDPLITE-RECV":      {Reason: "IPPROTO_UDPLITE recv", Platforms: PlatLinux},
	"UDPLITE-RECVFROM":  {Reason: "IPPROTO_UDPLITE recvfrom", Platforms: PlatLinux},
	"UDPLITE-SENDTO":    {Reason: "IPPROTO_UDPLITE sendto", Platforms: PlatLinux},
	"UDPLITE4-CONNECT":  {Reason: "IPv4 IPPROTO_UDPLITE connect", Platforms: PlatLinux},
	"UDPLITE4-DATAGRAM": {Reason: "IPv4 IPPROTO_UDPLITE datagram", Platforms: PlatLinux},
	"UDPLITE4-LISTEN":   {Reason: "IPv4 IPPROTO_UDPLITE listen", Platforms: PlatLinux},
	"UDPLITE4-RECV":     {Reason: "IPv4 IPPROTO_UDPLITE recv", Platforms: PlatLinux},
	"UDPLITE4-RECVFROM": {Reason: "IPv4 IPPROTO_UDPLITE recvfrom", Platforms: PlatLinux},
	"UDPLITE4-SENDTO":   {Reason: "IPv4 IPPROTO_UDPLITE sendto", Platforms: PlatLinux},
	"UDPLITE6-CONNECT":  {Reason: "IPv6 IPPROTO_UDPLITE connect", Platforms: PlatLinux},
	"UDPLITE6-DATAGRAM": {Reason: "IPv6 IPPROTO_UDPLITE datagram", Platforms: PlatLinux},
	"UDPLITE6-LISTEN":   {Reason: "IPv6 IPPROTO_UDPLITE listen", Platforms: PlatLinux},
	"UDPLITE6-RECV":     {Reason: "IPv6 IPPROTO_UDPLITE recv", Platforms: PlatLinux},
	"UDPLITE6-RECVFROM": {Reason: "IPv6 IPPROTO_UDPLITE recvfrom", Platforms: PlatLinux},
	"UDPLITE6-SENDTO":   {Reason: "IPv6 IPPROTO_UDPLITE sendto", Platforms: PlatLinux},
}

// ExpectedMissingAddressAliases are classic addressnames[] aliases whose
// canonical Go opener is already registered. PR C implements central alias
// resolution for these names. Do not add DCCP, DTLS, UDPLITE, or ACCEPT here.
//
// Values are the classic canonical addrdesc names.
var ExpectedMissingAddressAliases = map[string]string{
	"ABSTRACT":     "ABSTRACT-CLIENT",
	"DATAGRAM":     "SOCKET-DATAGRAM",
	"DGRAM":        "SOCKET-DATAGRAM",
	"IF":           "INTERFACE",
	"INET":         "TCP-CONNECT",
	"INET-L":       "TCP-LISTEN",
	"INET-LISTEN":  "TCP-LISTEN",
	"INET4":        "TCP4-CONNECT",
	"INET4-L":      "TCP4-LISTEN",
	"INET4-LISTEN": "TCP4-LISTEN",
	"INET6":        "TCP6-CONNECT",
	"INET6-L":      "TCP6-LISTEN",
	"INET6-LISTEN": "TCP6-LISTEN",
	"IP-DGRAM":     "IP-DATAGRAM",
	"IP-SEND":      "IP-SENDTO",
	"IP4-DGRAM":    "IP4-DATAGRAM",
	"IP4-SEND":     "IP4-SENDTO",
	"IP6-DGRAM":    "IP6-DATAGRAM",
	"IP6-SEND":     "IP6-SENDTO",
	"LOCAL":        "UNIX-CONNECT",
	"SENDTO":       "SOCKET-SENDTO",
	"SOCKS":        "SOCKS4",
	"UDP-DGRAM":    "UDP-DATAGRAM",
	"UDP4-DGRAM":   "UDP4-DATAGRAM",
	"UDP6-DGRAM":   "UDP6-DATAGRAM",
	"UNIX-SEND":    "UNIX-SENDTO",
}
