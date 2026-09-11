package optionmeta

// IsolationUnsupportedReason is the rejection text for process-wide
// credential and root-change options.
const IsolationUnsupportedReason = "process-wide credentials/root changes require process isolation"

var isolationOptions = []Option{
	{Canonical: "chroot",
		Isolation: true, Hidden: true,
	},
	{Canonical: "chroot-early",
		Isolation: true, Hidden: true,
	},
	{Canonical: "setuid",
		Isolation: true, Hidden: true,
	},
	{Canonical: "setuid-early",
		Isolation: true, Hidden: true,
	},
	{Canonical: "setgid",
		Isolation: true, Hidden: true,
	},
	{Canonical: "setgid-early",
		Isolation: true, Hidden: true,
	},
	{Canonical: "substuser", ParserAliases: []string{"su"},
		Isolation: true, Hidden: true,
	},
	{Canonical: "substuser-delayed", ParserAliases: []string{"su-d"},
		Isolation: true, Hidden: true,
	},
	{Canonical: "substuser-early",
		Isolation: true, Hidden: true,
	},
}
