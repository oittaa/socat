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

	// Intentional compatibility exception: Linux deprecated UDP-Lite in
	// 2023 and removed its IPv4/IPv6 socket support in Linux 7.1. Native
	// Windows and Darwin do not provide it, so this port does not emulate it.
	"UDPLITE":           "UDP-Lite is intentionally unsupported (removed from Linux 7.1)",
	"UDPLITE-CONNECT":   "UDP-Lite is intentionally unsupported",
	"UDPLITE-DATAGRAM":  "UDP-Lite is intentionally unsupported",
	"UDPLITE-DGRAM":     "UDP-Lite is intentionally unsupported",
	"UDPLITE-L":         "UDP-Lite is intentionally unsupported",
	"UDPLITE-LISTEN":    "UDP-Lite is intentionally unsupported",
	"UDPLITE-RECV":      "UDP-Lite is intentionally unsupported",
	"UDPLITE-RECVFROM":  "UDP-Lite is intentionally unsupported",
	"UDPLITE-SEND":      "UDP-Lite is intentionally unsupported",
	"UDPLITE-SENDTO":    "UDP-Lite is intentionally unsupported",
	"UDPLITE4":          "UDP-Lite is intentionally unsupported",
	"UDPLITE4-CONNECT":  "UDP-Lite is intentionally unsupported",
	"UDPLITE4-DATAGRAM": "UDP-Lite is intentionally unsupported",
	"UDPLITE4-DGRAM":    "UDP-Lite is intentionally unsupported",
	"UDPLITE4-L":        "UDP-Lite is intentionally unsupported",
	"UDPLITE4-LISTEN":   "UDP-Lite is intentionally unsupported",
	"UDPLITE4-RECV":     "UDP-Lite is intentionally unsupported",
	"UDPLITE4-RECVFROM": "UDP-Lite is intentionally unsupported",
	"UDPLITE4-SEND":     "UDP-Lite is intentionally unsupported",
	"UDPLITE4-SENDTO":   "UDP-Lite is intentionally unsupported",
	"UDPLITE6":          "UDP-Lite is intentionally unsupported",
	"UDPLITE6-CONNECT":  "UDP-Lite is intentionally unsupported",
	"UDPLITE6-DATAGRAM": "UDP-Lite is intentionally unsupported",
	"UDPLITE6-DGRAM":    "UDP-Lite is intentionally unsupported",
	"UDPLITE6-L":        "UDP-Lite is intentionally unsupported",
	"UDPLITE6-LISTEN":   "UDP-Lite is intentionally unsupported",
	"UDPLITE6-RECV":     "UDP-Lite is intentionally unsupported",
	"UDPLITE6-RECVFROM": "UDP-Lite is intentionally unsupported",
	"UDPLITE6-SEND":     "UDP-Lite is intentionally unsupported",
	"UDPLITE6-SENDTO":   "UDP-Lite is intentionally unsupported",

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
// Go opener is not registered. Empty after ACCEPT-FD / ACCEPT (PR F).
var ExpectedMissingCanonicalAddresses = map[string]Gap{}

// ExpectedMissingAddressAliases are classic addressnames[] aliases whose
// canonical Go opener is already registered but the alias is not yet
// resolved by the address registry. Empty after PR C (central alias
// resolution in xio). Do not add DCCP, DTLS, or readline here: those
// families stay unsupported. ACCEPT is a public alias of ACCEPT-FD and is
// registered with Syntax on Unix (PR F).
//
// Classic baseline: tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba;
// official master af5388c898c7bb60997935aee93c223deba60c4a.
// Values are the classic canonical addrdesc names.
var ExpectedMissingAddressAliases = map[string]string{}
