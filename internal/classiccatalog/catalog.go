// Package classiccatalog is the advertised option catalog from official
// classic socat -hhh output.
//
// Baseline: https://repo.or.cz/socat.git tag-1.8.1.3
// (12c08bf66d709fba17035ce95d85bd218428d9ba). Official master
// af5388c898c7bb60997935aee93c223deba60c4a currently has no option/help
// behavior differences from that tag (xiohelp.c, xioopts.h, optionnames[],
// and xio*.c are identical).
package classiccatalog

import "strings"

const (
	// Repo is the official classic socat Git URL.
	Repo = "https://repo.or.cz/socat.git"
	// Tag is the release used as the option/help baseline.
	Tag = "tag-1.8.1.3"
	// Commit is the Git object for Tag.
	Commit = "12c08bf66d709fba17035ce95d85bd218428d9ba"
	// Master is the official master commit checked for option/help drift.
	Master = "af5388c898c7bb60997935aee93c223deba60c4a"
)

// Entry is one advertised option spelling from classic `socat -hhh`.
type Entry struct {
	Spelling  string   // keyword printed by -hhh
	Canonical string   // optdesc defname; equals Spelling for primary entries
	Groups    []string // help group names (FD, SOCKET, IP4, IP6, …)
	Phase     string   // help phase name (SOCKET, PREBIND, LATE, …)
	Type      string   // help type name (BOOL, INT, INT:INT:BIN, …)
}

// IsAlias reports whether this spelling is printed as "is an alias for".
func (e Entry) IsAlias() bool {
	return e.Spelling != "" && e.Spelling != e.Canonical
}

// Lookup returns the catalog entry for an advertised spelling.
func Lookup(spelling string) (Entry, bool) {
	e, ok := Options[strings.ToLower(spelling)]
	return e, ok
}
