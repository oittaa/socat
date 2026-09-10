package parse

import "github.com/oittaa/socat/internal/optionmeta"

func init() {
	registerOptionAliases(tlsOptionAliases())
}

func tlsOptionAliases() map[string]string {
	aliases := map[string]string{
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
		"compress": "openssl-compress",
	}
	addUnsupportedTLSAliases(aliases)
	return aliases
}

func addUnsupportedTLSAliases(aliases map[string]string) {
	for _, opt := range optionmeta.UnsupportedTLS() {
		for _, alias := range opt.Aliases {
			if prev, ok := aliases[alias]; ok {
				panic("duplicate option alias " + alias + ": " + prev + " vs " + opt.Canonical)
			}
			aliases[alias] = opt.Canonical
		}
	}
}
