package optionmeta

// Transfer options.
var transferDefs = []Def{
	// Transfer
	{
		Canonical: "cr",
		Section:   SectionTransfer,
		Desc:      "convert NL to/from CR",
		Value:     NoValue,
		Apply:     Applicability{Unrestricted: true},
	},
	{
		Canonical:     "crnl",
		Section:       SectionTransfer,
		PublicAliases: []string{"crlf"},
		ParserAliases: []string{"crlf"},
		Desc:          "convert CR/NL",
		Value:         NoValue,
		Apply:         Applicability{Unrestricted: true},
	},
	{
		Canonical: "crorlf",
		Section:   SectionTransfer,
		Desc:      "convert CR or LF",
		Apply:     Applicability{Unrestricted: true},
	},
	{
		Canonical:     "ignoreeof",
		Section:       SectionTransfer,
		PublicAliases: []string{"ignoreof"},
		ParserAliases: []string{"ignoreof"},
		Desc:          "do not close on EOF",
		Apply:         Applicability{Unrestricted: true},
	},
	{
		Canonical: "null-eof",
		Section:   SectionTransfer,
		Desc:      "treat a zero-length read as EOF",
		Apply:     Applicability{Caps: CapSocket},
	},
	{
		Canonical:     "readbytes",
		Section:       SectionTransfer,
		PublicAliases: []string{"bytes"},
		ParserAliases: []string{"bytes"},
		Desc:          "read at most N bytes",
		Value:         SizeT,
		Apply:         Applicability{Unrestricted: true},
	},
	{
		Canonical: "lockfile",
		Section:   SectionTransfer,
		Desc:      "create lock file or fail if it exists (like -L)",
		Value:     RequiredString,
		Apply:     Applicability{Unrestricted: true},
	},
	{
		Canonical: "waitlock",
		Section:   SectionTransfer,
		Desc:      "wait until lock file is gone, then create it (1s poll)",
		Value:     RequiredString,
		Apply:     Applicability{Unrestricted: true},
	},
}
