package parse

func init() {
	registerOptionAliases(map[string]string{
		"proxyauth":          "proxy-authorization",
		"proxyauthfile":      "proxy-authorization-file",
		"openssl-capath":     "capath",
		"tls-capath":         "capath",
		"openssl-commonname": "commonname",
		"tls-commonname":     "commonname",
		"openssl-snihost":    "snihost",
		"tls-snihost":        "snihost",
		"openssl-no-sni":     "nosni",
		"tls-no-sni":         "nosni",
		"cipher":             "ciphers",
		"openssl-cipherlist": "ciphers",
	})
}
