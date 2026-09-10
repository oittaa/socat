package optionmeta

var isolationDefs = []Def{
	{Canonical: "chroot", Help: HelpHidden, Isolation: true},
	{Canonical: "chroot-early", Help: HelpHidden, Isolation: true},
	{Canonical: "setuid", Help: HelpHidden, Isolation: true},
	{Canonical: "setuid-early", Help: HelpHidden, Isolation: true},
	{Canonical: "setgid", Help: HelpHidden, Isolation: true},
	{Canonical: "setgid-early", Help: HelpHidden, Isolation: true},
	{Canonical: "substuser", ParserAliases: []string{"su"}, Help: HelpHidden, Isolation: true},
	{Canonical: "substuser-delayed", ParserAliases: []string{"su-d"}, Help: HelpHidden, Isolation: true},
	{Canonical: "substuser-early", Help: HelpHidden, Isolation: true},
}
