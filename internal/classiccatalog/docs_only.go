package classiccatalog

// DocsOnlyNotInThisBinary records official-documentation (and matching
// optionnames[] aliases) spellings that testdata/tag-1.8.1.3.hhh does not
// advertise. The dump is one configured binary: Linux glibc, OpenSSL 3,
// GNU Readline, libwrap, default configure flags (--enable-openssl-method
// and --enable-fips remain off).
//
// These names are required inputs for later compatibility work, but they
// must not be forged into the advertised -hhh catalog.
var DocsOnlyNotInThisBinary = map[string]string{
	"abort-threshold":      "documented; compiled only with HP-UX TCP_ABORT_THRESHOLD",
	"b3600":                "HP-UX B3600; not defined on Linux glibc",
	"b7200":                "HP-UX B7200; not defined on Linux glibc; completes FeatureCompleteSpellingCount",
	"b900":                 "HP-UX B900; not defined on Linux glibc",
	"binary":               "documented; compiled only with O_BINARY (Windows)",
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
	"noinherit":            "documented; compiled only with O_NOINHERIT",
	"noopt":                "documented; compiled only with TCP_NOOPT",
	"nopush":               "documented; compiled only with TCP_NOPUSH",
	"notail":               "documented fs-notail nickname; compiled only with FS_NOTAIL_FL",
	"nshare":               "documented; compiled only with O_NSHARE",
	"openssl-fips":         "optionnames[] alias of fips; requires --enable-fips",
	"openssl-method":       "optionnames[] alias of method; requires --enable-openssl-method",
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
	"text":                 "documented; compiled only with O_TEXT (Windows)",
	"tsoptena":             "documented; compiled only with OSF1 TCP_TSOPTENA",
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
	"handshake-timeout": "Go TLS, WebSocket, proxy, or SOCKS handshake bound extra",
	"origin":            "Go WebSocket Origin header extra",
	"recvtclass":        "Go alias of ipv6-recvtclass (C nickname, not in optionnames[])",
	"shut":              "Go shut=none|close|null extra; classic advertises shut-* names",
	"so-keepcnt":        "Go so-* alias of keepcnt / tcp-keepcnt",
	"so-keepidle":       "Go so-* alias of keepidle / tcp-keepidle",
	"so-keepintvl":      "Go so-* alias of keepintvl / tcp-keepintvl",
	"sockspassword":     "Go alias of sockspass",
	"tclass":            "Go alias of ipv6-tclass (C nickname, not in optionnames[])",
	"tls-capath":        "Go tls-* alias of capath",
	"tls-commonname":    "Go tls-* alias of commonname",
	"tls-no-sni":        "Go tls-* alias of nosni / no-sni",
	"tls-snihost":       "Go tls-* alias of snihost",
}
