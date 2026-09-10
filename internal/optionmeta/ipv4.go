package optionmeta

import "fmt"

// GetOnlyIPv4Option is one hidden IPv4 family that is recognized so it can be
// rejected as get-only instead of "unknown option".
type GetOnlyIPv4Option struct {
	Canonical string
	Aliases   []string
	Kernel    string
}

var getOnlyIPv4 = mustGetOnlyIPv4([]GetOnlyIPv4Option{
	{
		Canonical: "ip-mtu",
		Aliases:   []string{"ipmtu", "mtu"},
		Kernel:    "IP_MTU",
	},
	{
		Canonical: "ip-pktoptions",
		Aliases:   []string{"ippktoptions", "pktoptions", "pktopts"},
		Kernel:    "IP_PKTOPTIONS",
	},
})

// GetOnlyIPv4 returns a copy of the hidden get-only IPv4 option families.
func GetOnlyIPv4() []GetOnlyIPv4Option {
	return copyGetOnlyIPv4(getOnlyIPv4)
}

func mustGetOnlyIPv4(opts []GetOnlyIPv4Option) []GetOnlyIPv4Option {
	if err := validateGetOnlyIPv4(opts); err != nil {
		panic(err)
	}
	return opts
}

func copyGetOnlyIPv4(opts []GetOnlyIPv4Option) []GetOnlyIPv4Option {
	out := make([]GetOnlyIPv4Option, len(opts))
	for i, opt := range opts {
		opt.Aliases = append([]string(nil), opt.Aliases...)
		out[i] = opt
	}
	return out
}

func validateGetOnlyIPv4(opts []GetOnlyIPv4Option) error {
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
		if opt.Kernel == "" {
			return fmt.Errorf("%s: empty kernel name", opt.Canonical)
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
