package optionmeta

// Parser identity for TERMIOS nicknames whose syscall tables stay in xio.
var termiosAliasDefs = []Def{
	{Canonical: "termios-setflags", ParserAliases: []string{"setflags"}, Help: HelpHidden, Apply: Applicability{Caps: capTermios}},
	{Canonical: "echoprt", ParserAliases: []string{"prterase"}, Help: HelpHidden, Apply: Applicability{Caps: capTermios}},
	{Canonical: "vintr", ParserAliases: []string{"intr"}, Help: HelpHidden, Apply: Applicability{Caps: capTermios}},
	{Canonical: "vquit", ParserAliases: []string{"quit"}, Help: HelpHidden, Apply: Applicability{Caps: capTermios}},
	{Canonical: "verase", ParserAliases: []string{"erase"}, Help: HelpHidden, Apply: Applicability{Caps: capTermios}},
	{Canonical: "vkill", ParserAliases: []string{"kill"}, Help: HelpHidden, Apply: Applicability{Caps: capTermios}},
	{Canonical: "veof", ParserAliases: []string{"eof"}, Help: HelpHidden, Apply: Applicability{Caps: capTermios}},
	{Canonical: "veol", ParserAliases: []string{"eol"}, Help: HelpHidden, Apply: Applicability{Caps: capTermios}},
	{Canonical: "veol2", ParserAliases: []string{"eol2"}, Help: HelpHidden, Apply: Applicability{Caps: capTermios}},
	{Canonical: "vmin", ParserAliases: []string{"min"}, Help: HelpHidden, Apply: Applicability{Caps: capTermios}},
	{Canonical: "vtime", ParserAliases: []string{"time"}, Help: HelpHidden, Apply: Applicability{Caps: capTermios}},
	{Canonical: "vstart", ParserAliases: []string{"start"}, Help: HelpHidden, Apply: Applicability{Caps: capTermios}},
	{Canonical: "vstop", ParserAliases: []string{"stop"}, Help: HelpHidden, Apply: Applicability{Caps: capTermios}},
	{Canonical: "vsusp", ParserAliases: []string{"susp"}, Help: HelpHidden, Apply: Applicability{Caps: capTermios}},
	{Canonical: "vwerase", ParserAliases: []string{"werase"}, Help: HelpHidden, Apply: Applicability{Caps: capTermios}},
	{Canonical: "vlnext", ParserAliases: []string{"lnext"}, Help: HelpHidden, Apply: Applicability{Caps: capTermios}},
	{Canonical: "vdiscard", ParserAliases: []string{"discard"}, Help: HelpHidden, Apply: Applicability{Caps: capTermios}},
	{Canonical: "vreprint", ParserAliases: []string{"reprint", "rprnt"}, Help: HelpHidden, Apply: Applicability{Caps: capTermios}},
	{Canonical: "vswtc", ParserAliases: []string{"swtc", "swtch"}, Help: HelpHidden, Apply: Applicability{Caps: capTermios}},
}

var hiddenMiscDefs = []Def{
	{
		Canonical: "ipv6-recverr",
		Help:      HelpHidden,
		Apply:     Applicability{Caps: capIP6},
	},
}
