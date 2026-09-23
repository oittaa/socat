package optionmeta

var namespaceOptions = []Option{
	{Canonical: "netns", Kind: KindString,
		Desc: "open this address in a Linux network namespace",
	},
}
