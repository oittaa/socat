package optionmeta

// Parser identity for TERMIOS nicknames whose syscall tables stay in xio.
var termiosAliasDefs = []Def{
	{Canonical: "termios-setflags", ParserAliases: []string{"setflags"}, Help: HelpHidden, Apply: Applicability{Caps: CapTermios}},
	{Canonical: "echoprt", ParserAliases: []string{"prterase"}, Help: HelpHidden, Apply: Applicability{Caps: CapTermios}},
	{Canonical: "vintr", ParserAliases: []string{"intr"}, Help: HelpHidden, Apply: Applicability{Caps: CapTermios}},
	{Canonical: "vquit", ParserAliases: []string{"quit"}, Help: HelpHidden, Apply: Applicability{Caps: CapTermios}},
	{Canonical: "verase", ParserAliases: []string{"erase"}, Help: HelpHidden, Apply: Applicability{Caps: CapTermios}},
	{Canonical: "vkill", ParserAliases: []string{"kill"}, Help: HelpHidden, Apply: Applicability{Caps: CapTermios}},
	{Canonical: "veof", ParserAliases: []string{"eof"}, Help: HelpHidden, Apply: Applicability{Caps: CapTermios}},
	{Canonical: "veol", ParserAliases: []string{"eol"}, Help: HelpHidden, Apply: Applicability{Caps: CapTermios}},
	{Canonical: "veol2", ParserAliases: []string{"eol2"}, Help: HelpHidden, Apply: Applicability{Caps: CapTermios}},
	{Canonical: "vmin", ParserAliases: []string{"min"}, Help: HelpHidden, Apply: Applicability{Caps: CapTermios}},
	{Canonical: "vtime", ParserAliases: []string{"time"}, Help: HelpHidden, Apply: Applicability{Caps: CapTermios}},
	{Canonical: "vstart", ParserAliases: []string{"start"}, Help: HelpHidden, Apply: Applicability{Caps: CapTermios}},
	{Canonical: "vstop", ParserAliases: []string{"stop"}, Help: HelpHidden, Apply: Applicability{Caps: CapTermios}},
	{Canonical: "vsusp", ParserAliases: []string{"susp"}, Help: HelpHidden, Apply: Applicability{Caps: CapTermios}},
	{Canonical: "vwerase", ParserAliases: []string{"werase"}, Help: HelpHidden, Apply: Applicability{Caps: CapTermios}},
	{Canonical: "vlnext", ParserAliases: []string{"lnext"}, Help: HelpHidden, Apply: Applicability{Caps: CapTermios}},
	{Canonical: "vdiscard", ParserAliases: []string{"discard"}, Help: HelpHidden, Apply: Applicability{Caps: CapTermios}},
	{Canonical: "vreprint", ParserAliases: []string{"reprint", "rprnt"}, Help: HelpHidden, Apply: Applicability{Caps: CapTermios}},
	{Canonical: "vswtc", ParserAliases: []string{"swtc", "swtch"}, Help: HelpHidden, Apply: Applicability{Caps: CapTermios}},
}

var hiddenMiscDefs = []Def{
	{
		Canonical: "ipv6-recverr",
		Help:      HelpHidden,
		Apply:     Applicability{Caps: CapIP6},
	},
}
