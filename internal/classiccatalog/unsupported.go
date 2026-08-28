package classiccatalog

// unsupportedOpenSSL is documented OpenSSL/TLS spellings this port rejects
// instead of advertising. They must not appear in ImplementationBacklog.
// Classic baseline: tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba;
// official master af5388c898c7bb60997935aee93c223deba60c4a.
// openssl-method and openssl-fips are OptionalParserOnlyAliases of method/fips.
var unsupportedOpenSSL = map[string]string{
	"method":              "OpenSSL method= needs --enable-openssl-method; this port has no OpenSSL engine (README Unsupported / security-related)",
	"fips":                "OpenSSL fips= needs --enable-fips; this port has no FIPS module (README Unsupported / security-related)",
	"openssl-egd":         "EGD path feeds OpenSSL RNG; Go uses crypto/rand (rejected when enabled)",
	"egd":                 "alias of openssl-egd; rejected when enabled",
	"openssl-pseudo":      "OpenSSL pseudo-random; Go uses crypto/rand (rejected when enabled)",
	"pseudo":              "alias of openssl-pseudo; rejected when enabled",
	"openssl-dhparam":     "SSL_CTX_set_tmp_dh; Go crypto/tls does not load DH params (rejected)",
	"openssl-dhparams":    "alias of openssl-dhparam; rejected",
	"dhparam":             "alias of openssl-dhparam; rejected",
	"dhparams":            "alias of openssl-dhparam; rejected",
	"dh":                  "alias of openssl-dhparam; rejected",
	"openssl-maxfraglen":  "SSL_CTX_set_tlsext_max_fragment_length is not in Go crypto/tls (rejected)",
	"maxfraglen":          "alias of openssl-maxfraglen; rejected",
	"openssl-maxsendfrag": "SSL_CTX_set_max_send_fragment is not in Go crypto/tls (rejected)",
	"maxsendfrag":         "alias of openssl-maxsendfrag; rejected",
}

// unsupportedReadline is GROUP_READLINE. GNU readline is not implemented
// (#undef WITH_READLINE in -V).
var unsupportedReadline = map[string]string{
	"history":      "READLINE is not implemented",
	"history-file": "READLINE is not implemented",
	"noecho":       "READLINE is not implemented",
	"noprompt":     "READLINE is not implemented",
	"prompt":       "READLINE is not implemented",
}

// unsupportedDCCP is GROUP_DCCP. DCCP addresses are not implemented.
var unsupportedDCCP = map[string]string{
	"ccid":          "DCCP is not implemented",
	"dccp-set-ccid": "DCCP is not implemented",
}

// unsupportedUDPLITE contains the public UDP-Lite socket options retained in
// the classic catalog. Linux removed UDP-Lite in 7.1; this intentional
// compatibility exception is documented in README.md.
var unsupportedUDPLITE = map[string]string{
	"udplite-send-cscov": "UDP-Lite is intentionally unsupported (removed from Linux 7.1)",
	"udplite-recv-cscov": "UDP-Lite is intentionally unsupported (removed from Linux 7.1)",
}

// unsupportedNoopSockopts are catalog-advertised on Linux classic but would
// be silent no-ops here. Do not advertise them until a real implementation
// exists (do not invent incompatible semantics).
var unsupportedNoopSockopts = map[string]string{
	"so-bsdcompat": "Linux SO_BSDCOMPAT is a kernel no-op; this port does not advertise a no-op (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba; official master af5388c898c7bb60997935aee93c223deba60c4a)",
	"bsdcompat":    "alias of so-bsdcompat; not advertised (kernel no-op)",
}
