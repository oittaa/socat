package optionmeta

var getOnlyIPv4Options = []Option{
	{Canonical: "ip-mtu", Kind: KindGetOnly, ParserAliases: []string{"ipmtu", "mtu"},
		Kernel: "IP_MTU", Hidden: true, Scope: AddressScope{Caps: capIP4IP6},
	},
	{Canonical: "ip-pktoptions", Kind: KindGetOnly, ParserAliases: []string{"ippktoptions", "pktoptions", "pktopts"},
		Kernel: "IP_PKTOPTIONS", Hidden: true, Scope: AddressScope{Caps: capIP4IP6},
	},
}

var rejectedIPv6Options = []Option{
	{Canonical: "ipv6-recverr", Kind: KindRecvErr,
		Hidden: true, Scope: AddressScope{Caps: capIP6},
	},
}
