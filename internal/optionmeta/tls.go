// Package optionmeta holds hidden option recognition entries shared by
// the parser, CLI, and runtime.
package optionmeta

import (
	"fmt"
	"strings"
)

// CLIValueKind selects the existing CLI validator for a hidden TLS option.
type CLIValueKind uint8

const (
	// RequiredString requires a non-empty value.
	RequiredString CLIValueKind = iota + 1
	// OptionalBool accepts omission, 0, or 1.
	OptionalBool
	// OptionalSignedInteger accepts omission or a signed integer.
	OptionalSignedInteger
)

// UnsupportedTLSOption is one hidden OpenSSL family that is recognized so it
// can be rejected with a precise reason.
type UnsupportedTLSOption struct {
	Canonical       string
	Aliases         []string
	CLIValue        CLIValueKind
	TLSRejectReason string
}

var unsupportedTLS = mustUnsupportedTLS([]UnsupportedTLSOption{
	{
		Canonical:       "openssl-method",
		Aliases:         []string{"opensslmethod", "method"},
		CLIValue:        RequiredString,
		TLSRejectReason: "stream TLS only",
	},
	{
		Canonical:       "openssl-fips",
		Aliases:         []string{"fips"},
		CLIValue:        OptionalBool,
		TLSRejectReason: "Go crypto/tls has no OpenSSL FIPS module",
	},
	{
		Canonical:       "openssl-egd",
		Aliases:         []string{"egd"},
		CLIValue:        RequiredString,
		TLSRejectReason: "Go does not use EGD for randomness",
	},
	{
		Canonical:       "openssl-pseudo",
		Aliases:         []string{"pseudo"},
		CLIValue:        OptionalBool,
		TLSRejectReason: "Go crypto/tls does not use OpenSSL pseudo-random bytes",
	},
	{
		Canonical:       "openssl-dhparam",
		Aliases:         []string{"openssl-dhparams", "dhparam", "dhparams", "dh"},
		CLIValue:        RequiredString,
		TLSRejectReason: "Go crypto/tls does not load DH parameters",
	},
	{
		Canonical:       "openssl-maxfraglen",
		Aliases:         []string{"maxfraglen"},
		CLIValue:        OptionalSignedInteger,
		TLSRejectReason: "Go crypto/tls has no max fragment length option",
	},
	{
		Canonical:       "openssl-maxsendfrag",
		Aliases:         []string{"maxsendfrag"},
		CLIValue:        OptionalSignedInteger,
		TLSRejectReason: "Go crypto/tls has no max send fragment option",
	},
})

// UnsupportedTLS returns a copy of the hidden TLS option families.
func UnsupportedTLS() []UnsupportedTLSOption {
	return copyUnsupportedTLS(unsupportedTLS)
}

func mustUnsupportedTLS(opts []UnsupportedTLSOption) []UnsupportedTLSOption {
	if err := validateUnsupportedTLS(opts); err != nil {
		panic(err)
	}
	return opts
}

func copyUnsupportedTLS(opts []UnsupportedTLSOption) []UnsupportedTLSOption {
	out := make([]UnsupportedTLSOption, len(opts))
	for i, opt := range opts {
		opt.Aliases = append([]string(nil), opt.Aliases...)
		out[i] = opt
	}
	return out
}

func validateUnsupportedTLS(opts []UnsupportedTLSOption) error {
	seenCanonical := make(map[string]struct{}, len(opts))
	seenAlias := make(map[string]struct{})
	for _, opt := range opts {
		if err := validateMetaName(opt.Canonical, "canonical"); err != nil {
			return err
		}
		if _, ok := seenCanonical[opt.Canonical]; ok {
			return fmt.Errorf("duplicate canonical name %q", opt.Canonical)
		}
		seenCanonical[opt.Canonical] = struct{}{}
		if opt.TLSRejectReason == "" {
			return fmt.Errorf("%s: empty TLS reject reason", opt.Canonical)
		}
		if err := validateCLIValueKind(opt.CLIValue); err != nil {
			return fmt.Errorf("%s: %w", opt.Canonical, err)
		}
		for _, alias := range opt.Aliases {
			if err := validateMetaName(alias, "alias"); err != nil {
				return fmt.Errorf("%s: %w", opt.Canonical, err)
			}
			if alias == opt.Canonical {
				return fmt.Errorf("%s: alias repeats canonical name", opt.Canonical)
			}
			if _, ok := seenAlias[alias]; ok {
				return fmt.Errorf("duplicate alias %q", alias)
			}
			seenAlias[alias] = struct{}{}
		}
	}
	for alias := range seenAlias {
		if _, ok := seenCanonical[alias]; ok {
			return fmt.Errorf("alias %q collides with a canonical name", alias)
		}
	}
	return nil
}

func validateMetaName(name, kind string) error {
	if name == "" {
		return fmt.Errorf("empty %s name", kind)
	}
	if name != strings.ToLower(name) {
		return fmt.Errorf("non-lowercase %s name %q", kind, name)
	}
	return nil
}

func validateCLIValueKind(kind CLIValueKind) error {
	switch kind {
	case RequiredString, OptionalBool, OptionalSignedInteger:
		return nil
	default:
		return fmt.Errorf("unknown CLI value kind %d", kind)
	}
}
