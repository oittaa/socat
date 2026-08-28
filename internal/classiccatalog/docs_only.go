package classiccatalog

// DocsOnlyNotInThisBinary records official-documentation spellings that
// testdata/tag-1.8.1.3.hhh does not advertise. The dump is one configured
// binary: Linux glibc, OpenSSL 3, GNU Readline, libwrap, default configure
// flags (--enable-openssl-method and --enable-fips remain off).
//
// These names are required inputs for ClassifyOption (implementation backlog,
// unsupported, or foreign). They must not be forged into the advertised -hhh
// catalog. RequiredPublicSpellings unions this set with Options, minus
// IntentionalPublicOmissions. Parser-only optionnames[] aliases that the man
// page does not document (including openssl-fips and openssl-method) belong
// in OptionalParserOnlyAliases.
var DocsOnlyNotInThisBinary = map[string]string{
	"abort-threshold":      "documented; compiled only with HP-UX TCP_ABORT_THRESHOLD",
	"b3600":                "HP-UX B3600; not defined on Linux glibc",
	"b900":                 "HP-UX B900; not defined on Linux glibc",
	"conn-abort-threshold": "documented; compiled only with HP-UX TCP_CONN_ABORT_THRESHOLD",
	"dsusp":                "documented; compiled only with HP-UX VDSUSP",
	"fips":                 "documented OPENSSL fips; requires --enable-fips",
	"i-pop-all":            "documented; compiled only with I_POP",
	"i-push":               "documented; compiled only with I_PUSH",
	"iff-dynamic":          "documented IFF_DYNAMIC; commented out of optionnames[]",
	"ip-recvdstaddr":       "documented; compiled only with IP_RECVDSTADDR",
	"ip-recvif":            "documented; compiled only with IP_RECVIF",
	"keepinit":             "documented; compiled only with OSF1 TCP_KEEPINIT",
	"md5sig":               "documented; compiled only with TCP_MD5SUM",
	"method":               "documented OPENSSL method=; requires --enable-openssl-method",
	"noopt":                "documented; compiled only with TCP_NOOPT",
	"nopush":               "documented; compiled only with TCP_NOPUSH",
	"notail":               "documented fs-notail nickname; absent from optionnames[] even when FS_NOTAIL_FL exists",
	"nshare":               "documented; compiled only with O_NSHARE",
	"paws":                 "documented; compiled only with OSF1 TCP_PAWS",
	"res-aaonly":           "documented resolver option; compiled only with WITH_AA_ONLY",
	"res-primary":          "documented resolver option; compiled only with WITH_RES_PRIMARY",
	"rfc1323":              "documented; compiled only with TCP_RFC1323",
	"rshare":               "documented; compiled only with O_RSHARE",
	"sack-disable":         "documented; compiled only with TCP_SACK_DISABLE",
	"sackena":              "documented; compiled only with OSF1 TCP_SACKENA",
	"sctp-maxseg":          "documented; compiled only with SCTP_MAXSEG",
	"sctp-nodelay":         "documented; compiled only with SCTP_NODELAY",
	"signature-enable":     "documented; compiled only with TCP_SIGNATURE_ENABLE",
	"stdurg":               "documented; compiled only with TCP_STDURG",
	"tsoptena":             "documented; compiled only with OSF1 TCP_TSOPTENA",
	"udp-ignore-peerport":  "documented UDP-DATAGRAM option; not present in optionnames[] (see unsupported_udp.go)",
}

// OptionalParserOnlyAliases are C optionnames[] spellings that this configured
// binary does not advertise and that the official man page does not document
// as public OPTION_ names. They are accepted by the classic parser on some
// hosts but are not compatibility requirements. openssl-fips and openssl-method
// are parser aliases of documented fips and method.
var OptionalParserOnlyAliases = map[string]string{
	"aaonly":                   "optionnames[] alias of res-aaonly; WITH_AA_ONLY",
	"audit":                    "optionnames[] SO_AUDIT (AIX)",
	"cibaud":                   "optionnames[] termios CIBAUD",
	"cksumrecv":                "optionnames[] alias of so-cksumrecv",
	"cleanup":                  "optionnames[] host-specific",
	"defer":                    "optionnames[] O_DEFER",
	"delay":                    "optionnames[] O_DELAY",
	"dgram-errind":             "optionnames[] SO_DGRAM_ERRIND",
	"dgramerrind":              "optionnames[] alias of dgram-errind",
	"dontlinger":               "optionnames[] SO_DONTLINGER",
	"flowinfo":                 "optionnames[] alias of ipv6-flowinfo",
	"ipv6-flowinfo":            "optionnames[] IPV6_FLOWINFO",
	"kernaccept":               "optionnames[] SO_KERNACCEPT",
	"noreuseaddr":              "optionnames[] SO_NOREUSEADDR",
	"o-defer":                  "optionnames[] O_DEFER",
	"o-delay":                  "optionnames[] O_DELAY",
	"o-nshare":                 "optionnames[] alias of nshare; O_NSHARE",
	"o-priv":                   "optionnames[] O_PRIV",
	"o-rshare":                 "optionnames[] alias of rshare; O_RSHARE",
	"o_defer":                  "optionnames[] O_DEFER",
	"o_delay":                  "optionnames[] O_DELAY",
	"o_nshare":                 "optionnames[] alias of nshare; O_NSHARE",
	"o_priv":                   "optionnames[] O_PRIV",
	"o_rshare":                 "optionnames[] alias of rshare; O_RSHARE",
	"openssl-fips":             "optionnames[] alias of documented fips; not a public man spelling",
	"openssl-method":           "optionnames[] alias of documented method; not a public man spelling",
	"pop-all":                  "optionnames[] alias of i-pop-all",
	"port":                     "optionnames[] host-specific",
	"primary":                  "optionnames[] alias of res-primary",
	"priv":                     "optionnames[] O_PRIV",
	"push":                     "optionnames[] alias of i-push",
	"sctp-maxseg-late":         "optionnames[] late SCTP_MAXSEG",
	"so-audit":                 "optionnames[] SO_AUDIT (AIX)",
	"so-cksumrecv":             "optionnames[] SO_CKSUMRECV",
	"so-dgram-errind":          "optionnames[] SO_DGRAM_ERRIND",
	"so-dontlinger":            "optionnames[] SO_DONTLINGER",
	"so-kernaccept":            "optionnames[] SO_KERNACCEPT",
	"so-noreuseaddr":           "optionnames[] SO_NOREUSEADDR",
	"so-use-ifbufs":            "optionnames[] SO_USE_IFBUFS",
	"so-useloopback":           "optionnames[] SO_USELOOPBACK",
	"streams-i-pop-all":        "optionnames[] alias of i-pop-all",
	"streams-i-push":           "optionnames[] alias of i-push",
	"tcp-abort-threshold":      "optionnames[] alias of abort-threshold",
	"tcp-conn-abort-threshold": "optionnames[] alias of conn-abort-threshold",
	"tcp-keepinit":             "optionnames[] alias of keepinit",
	"tcp-noopt":                "optionnames[] alias of noopt",
	"tcp-nopush":               "optionnames[] alias of nopush",
	"tcp-paws":                 "optionnames[] alias of paws",
	"tcp-rfc1323":              "optionnames[] alias of rfc1323",
	"tcp-sack-disable":         "optionnames[] alias of sack-disable",
	"tcp-sackena":              "optionnames[] alias of sackena",
	"tcp-signature-enable":     "optionnames[] alias of signature-enable",
	"tcp-stdurg":               "optionnames[] alias of stdurg",
	"tcp-tsoptena":             "optionnames[] alias of tsoptena",
	"use-ifbufs":               "optionnames[] alias of so-use-ifbufs",
	"useifbufs":                "optionnames[] alias of so-use-ifbufs",
	"useloopback":              "optionnames[] alias of so-useloopback",
	"vdsusp":                   "optionnames[] alias of dsusp",
}

// IntentionalPublicOmissions are classic public spellings this port records
// in the catalog but deliberately does not treat as compatibility
// requirements. cool-write is deprecated (use children-shutup); Go must not
// re-advertise it, and the audit must not tell later agents to implement it.
// ip-recverr / ipv6-recverr are recognized so they can be rejected with a
// precise error instead of a silent no-op; they are not advertised because
// this port has no MSG_ERRQUEUE ReadMsg path.
var IntentionalPublicOmissions = map[string]string{
	"cool-write":   "deprecated; this port stopped advertising it (use children-shutup)",
	"coolwrite":    "deprecated alias of cool-write; this port stopped advertising it",
	"ip-recverr":   "recognized and rejected: no MSG_ERRQUEUE ReadMsg path (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master af5388c898c7bb60997935aee93c223deba60c4a)",
	"recverr":      "alias of ip-recverr; rejected, not advertised",
	"iprecverr":    "alias of ip-recverr; rejected, not advertised",
	"ipv6-recverr": "recognized and rejected: no MSG_ERRQUEUE ReadMsg path (GROUP_IP6)",
}

// GoOnlyHelpAllowlist is names this port advertises in -hh/-hhh that classic
// tag-1.8.1.3 -hhh does not print. Do not add a classic spelling here to
// start advertising an unimplemented option.
var GoOnlyHelpAllowlist = map[string]string{ // #nosec G101 -- option names and reasons, not secrets
	"alpn":              "Go QUIC and HTTP/2/3 CONNECT extra",
	"ca":                "Go short alias of cafile / openssl-cafile",
	"child-shutup":      "Go advertised alias of children-shutup (C nickname, not in optionnames[])",
	"crorlf":            "Go CR-or-LF line conversion extra",
	"h2c":               "Go cleartext HTTP/2 CONNECT extra",
	"handshake-timeout": "Go TLS, WebSocket, QUIC, PROXY, or SOCKS handshake bound extra",
	"notail":            "documented fs-notail nickname omitted from optionnames[] even with FS_NOTAIL_FL (tag-1.8.1.3 12c08bf; master af5388c). Advertised on Linux.",
	"origin":            "Go WebSocket Origin header extra",
	"recvtclass":        "Go alias of ipv6-recvtclass (C nickname, not in optionnames[])",
	"shut":              "Go shut=none|down|close|null extra; classic advertises shut-* names",
	"so-keepcnt":        "Go so-* alias of keepcnt / tcp-keepcnt",
	"so-keepidle":       "Go so-* alias of keepidle / tcp-keepidle",
	"so-keepintvl":      "Go so-* alias of keepintvl / tcp-keepintvl",
	"sockspassword":     "Go alias of sockspass",
	"tclass":            "Go alias of ipv6-tclass (C nickname, not in optionnames[])",
	"tls-capath":        "Go tls-* alias of capath",
	"tls-commonname":    "Go tls-* alias of commonname",
	"tls-no-sni":        "Go tls-* alias of nosni / no-sni",
	"tls-snihost":       "Go tls-* alias of snihost",
	"sctp-maxseg":       "documented SCTP_MAXSEG; Linux reference -hhh omitted it (no SCTP_MAXSEG in that binary)",
	"sctp-nodelay":      "documented SCTP_NODELAY; Linux reference -hhh omitted it (no SCTP_NODELAY in that binary)",
	"ip-recvdstaddr":    "documented IP_RECVDSTADDR; Linux reference -hhh omitted it. Advertised on Darwin; hidden elsewhere.",
	"ip-recvif":         "documented IP_RECVIF; Linux reference -hhh omitted it. Advertised on Darwin; hidden elsewhere.",
	"recvdstaddr":       "optionnames[] alias of ip-recvdstaddr; dump-omitted. Advertised on Darwin; hidden elsewhere.",
	"iprecvdstaddr":     "optionnames[] alias of ip-recvdstaddr; dump-omitted. Advertised on Darwin; hidden elsewhere.",
	"recvif":            "optionnames[] alias of ip-recvif; dump-omitted. Advertised on Darwin; hidden elsewhere.",
}
