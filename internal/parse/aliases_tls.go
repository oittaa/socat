package parse

func init() {
	registerOptionAliases(map[string]string{ // #nosec G101 -- option names, not secrets
		"proxyauth":     "proxy-authorization",
		"proxy-auth":    "proxy-authorization",
		"proxyauthfile": "proxy-authorization-file",
		"resolve":       "proxy-resolve",
		"resolv":        "proxy-resolve",
		"sockspassword": "sockspass",

		// Alias map so openssl-* / tls-* nicknames fold onto canonical names.
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

		// OPENSSL options Go crypto/tls cannot honor are still folded so CLI
		// validation can reject them (last-wins still applies; tlsopen rejects
		// instead of a no-op). Do not advertise these as working in -hhh.
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
