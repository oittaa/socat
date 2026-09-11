package optionmeta

var dtlsOptions = []Option{
	{Canonical: "dtls-mtu",
		Desc:  "maximum UDP payload in bytes (256..65507, default 1200)",
		Scope: AddressScope{AddressTypes: dtlsAddressTypes},
	},
	{Canonical: "dtls-migration",
		Desc:  "negotiate connection IDs and validated address migration (default on)",
		Scope: AddressScope{AddressTypes: dtlsAddressTypes},
	},
	{Canonical: "dtls-unfragmented-probes",
		Desc:  "confirm and discover path MTU on a dedicated socket (default on with migration)",
		Scope: AddressScope{AddressTypes: dtlsAddressTypes},
	},
}
