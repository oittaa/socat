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
// Go opener is not registered. ACCEPT-FD is PR F (Unix). UDPLITE* canonicals
// and their -L/-SEND/-DGRAM aliases were registered by #101 (Linux-only).
var ExpectedMissingCanonicalAddresses = map[string]Gap{
	"ACCEPT-FD": {Reason: "consume an already-accepted stream socket (PR F)", Platforms: PlatUnix},
}

// ExpectedMissingAddressAliases are classic addressnames[] aliases whose
// canonical Go opener is already registered but the alias is not yet
// resolved by the address registry. Empty after PR C (central alias
// resolution in xio). Do not add DCCP, DTLS, readline, or ACCEPT here:
// those families stay unsupported or unimplemented. UDPLITE-L /
// UDPLITE-SEND / UDPLITE-DGRAM are directly registered with the family
// (#101), not fallback aliases.
//
// Classic baseline: tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba;
// official master af5388c898c7bb60997935aee93c223deba60c4a.
// Values are the classic canonical addrdesc names.
var ExpectedMissingAddressAliases = map[string]string{}
