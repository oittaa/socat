package parse

func init() {
	registerOptionAliases(map[string]string{
		"proxyauth":     "proxy-authorization",
		"proxy-auth":    "proxy-authorization",
		"proxyauthfile": "proxy-authorization-file",
		"resolve":       "proxy-resolve",
		"resolv":        "proxy-resolve",

		// Public OPENSSL catalog nicknames for implemented TLS options.
		// Classic baseline: tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba;
		// official master af5388c898c7bb60997935aee93c223deba60c4a is the same
		// optionnames[] set for these spellings (xioopts.c / xio-openssl.c).
		"certificate":         "cert",
		"openssl-certificate": "cert",
		"openssl-key":         "key",
		"openssl-cafile":      "cafile",
		"ca":                  "cafile",
		"openssl-capath":      "capath",
		"tls-capath":          "capath",
		"openssl-verify":      "verify",
		"cn":                  "commonname",
		"openssl-commonname":  "commonname",
		"tls-commonname":      "commonname",
		"openssl-snihost":     "snihost",
		"tls-snihost":         "snihost",
		"no-sni":              "nosni",
		"openssl-no-sni":      "nosni",
		"tls-no-sni":          "nosni",
		"cipher":              "ciphers",
		"cipherlist":          "ciphers",
		"openssl-cipherlist":  "ciphers",
		"min-proto-version":   "openssl-min-proto-version",
		"min-version":         "openssl-min-proto-version",
		"max-proto-version":   "openssl-max-proto-version",
		"max-version":         "openssl-max-proto-version",

		// Classic OPENSSL options Go crypto/tls cannot honor. Folded so
		// last-option-wins still applies; tlsopen rejects them instead of
		// accepting a no-op. Do not advertise these as working in -hhh.
		"method":           "openssl-method",
		"opensslmethod":    "openssl-method",
		"fips":             "openssl-fips",
		"compress":         "openssl-compress",
		"egd":              "openssl-egd",
		"pseudo":           "openssl-pseudo",
		"dh":               "openssl-dhparam",
		"dhparam":          "openssl-dhparam",
		"dhparams":         "openssl-dhparam",
		"openssl-dhparams": "openssl-dhparam",
		"maxfraglen":       "openssl-maxfraglen",
		"maxsendfrag":      "openssl-maxsendfrag",
	})
}
