package optionmeta

var hiddenTLSDefs = []Def{
	{
		Canonical:       "openssl-method",
		ParserAliases:   []string{"opensslmethod", "method"},
		Help:            HelpHidden,
		Value:           RequiredString,
		Apply:           Applicability{Caps: capOpenSSL, AddressGroups: tlsAddressGroups()},
		TLSRejectReason: "stream TLS only",
	},
	{
		Canonical:       "openssl-fips",
		ParserAliases:   []string{"fips"},
		Help:            HelpHidden,
		Value:           OptionalBool,
		Apply:           Applicability{Caps: capOpenSSL, AddressGroups: tlsAddressGroups()},
		TLSRejectReason: "Go crypto/tls has no OpenSSL FIPS module",
	},
	{
		Canonical:       "openssl-egd",
		ParserAliases:   []string{"egd"},
		Help:            HelpHidden,
		Value:           RequiredString,
		Apply:           Applicability{Caps: capOpenSSL, AddressGroups: tlsAddressGroups()},
		TLSRejectReason: "Go does not use EGD for randomness",
	},
	{
		Canonical:       "openssl-pseudo",
		ParserAliases:   []string{"pseudo"},
		Help:            HelpHidden,
		Value:           OptionalBool,
		Apply:           Applicability{Caps: capOpenSSL, AddressGroups: tlsAddressGroups()},
		TLSRejectReason: "Go crypto/tls does not use OpenSSL pseudo-random bytes",
	},
	{
		Canonical:       "openssl-dhparam",
		ParserAliases:   []string{"openssl-dhparams", "dhparam", "dhparams", "dh"},
		Help:            HelpHidden,
		Value:           RequiredString,
		Apply:           Applicability{Caps: capOpenSSL, AddressGroups: tlsAddressGroups()},
		TLSRejectReason: "Go crypto/tls does not load DH parameters",
	},
	{
		Canonical:       "openssl-maxfraglen",
		ParserAliases:   []string{"maxfraglen"},
		Help:            HelpHidden,
		Value:           OptionalSignedInteger,
		Apply:           Applicability{Caps: capOpenSSL, AddressGroups: tlsAddressGroups()},
		TLSRejectReason: "Go crypto/tls has no max fragment length option",
	},
	{
		Canonical:       "openssl-maxsendfrag",
		ParserAliases:   []string{"maxsendfrag"},
		Help:            HelpHidden,
		Value:           OptionalSignedInteger,
		Apply:           Applicability{Caps: capOpenSSL, AddressGroups: tlsAddressGroups()},
		TLSRejectReason: "Go crypto/tls has no max send fragment option",
	},
}

// UnsupportedTLSOption is one hidden OpenSSL family recognized so it can be
// rejected with a precise reason.
type UnsupportedTLSOption struct {
	Canonical       string
	Aliases         []string
	CLIValue        ValueKind
	TLSRejectReason string
}

// UnsupportedTLS returns a copy of the hidden TLS option families.
func UnsupportedTLS() []UnsupportedTLSOption {
	var out []UnsupportedTLSOption
	for _, d := range catalog {
		if d.Help != HelpHidden || d.TLSRejectReason == "" {
			continue
		}
		out = append(out, UnsupportedTLSOption{
			Canonical:       d.Canonical,
			Aliases:         d.ParseAliases(),
			CLIValue:        d.Value,
			TLSRejectReason: d.TLSRejectReason,
		})
	}
	return out
}
