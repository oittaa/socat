package optionmeta

var getOnlyIPv4Defs = []Def{
	{
		Canonical:     "ip-mtu",
		ParserAliases: []string{"ipmtu", "mtu"},
		Help:          HelpHidden,
		Apply:         Applicability{Caps: capIP4IP6},
		Kernel:        "IP_MTU",
	},
	{
		Canonical:     "ip-pktoptions",
		ParserAliases: []string{"ippktoptions", "pktoptions", "pktopts"},
		Help:          HelpHidden,
		Apply:         Applicability{Caps: capIP4IP6},
		Kernel:        "IP_PKTOPTIONS",
	},
}

// GetOnlyIPv4Option is one hidden IPv4 family recognized so it can be
// rejected as get-only instead of "unknown option".
type GetOnlyIPv4Option struct {
	Canonical string
	Aliases   []string
	Kernel    string
}

// GetOnlyIPv4 returns a copy of the hidden get-only IPv4 option families.
func GetOnlyIPv4() []GetOnlyIPv4Option {
	var out []GetOnlyIPv4Option
	for _, d := range catalog {
		if d.Kernel == "" {
			continue
		}
		out = append(out, GetOnlyIPv4Option{
			Canonical: d.Canonical,
			Aliases:   d.ParseAliases(),
			Kernel:    d.Kernel,
		})
	}
	return out
}
