// Package classiccatalog is the advertised option catalog from official
// classic socat -hhh output.
//
// Baseline: https://repo.or.cz/socat.git tag-1.8.1.3
// (12c08bf66d709fba17035ce95d85bd218428d9ba). Official master
// af5388c898c7bb60997935aee93c223deba60c4a currently has no option/help
// behavior differences from that tag (xiohelp.c, xioopts.h, optionnames[],
// and xio*.c are identical).
//
// The checked-in dump is a feature-complete Ubuntu 26.04 / glibc 2.41+
// Linux build of that tag (OpenSSL, GNU Readline, and libwrap enabled by
// configure once the libraries are present). That binary advertises
// AdvertisedCount unique option spellings, including b7200 from a real
// <termios.h> `#define B7200 7200U`. Do not forge B7200 with CPPFLAGS.
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

	// AdvertisedCount is unique spellings in testdata/tag-1.8.1.3.hhh
	// from the feature-complete Linux official binary, including b7200.
	AdvertisedCount = 795
)

// FeatureCompleteDefines are socat -V macros a dump must have before it is
// compared to testdata/tag-1.8.1.3.hhh.
var FeatureCompleteDefines = []string{
	"WITH_OPENSSL",
	"WITH_READLINE",
	"WITH_LIBWRAP",
}

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
	name := strings.ToLower(spelling)
	if e, ok := Options[name]; ok {
		return e, true
	}
	p, ok := PlatformOnlyOptions[name]
	return p.Entry, ok
}

// RequiredPublicSpellings is the union of the reference -hhh names,
// platform-only advertised names, and documented public spellings that the
// reference binary does not print, minus IntentionalPublicOmissions.
// ClassifyOption splits this set into
// must-advertise, expected-missing (implementation backlog), unsupported,
// and foreign-on-this-GOOS. Undocumented parser-only aliases are not
// included; see OptionalParserOnlyAliases.
func RequiredPublicSpellings() map[string]struct{} {
	out := make(map[string]struct{}, len(Options)+len(PlatformOnlyOptions)+len(DocsOnlyNotInThisBinary))
	for name := range Options {
		if _, omit := IntentionalPublicOmissions[name]; omit {
			continue
		}
		out[name] = struct{}{}
	}
	for name := range DocsOnlyNotInThisBinary {
		if _, omit := IntentionalPublicOmissions[name]; omit {
			continue
		}
		out[name] = struct{}{}
	}
	for name := range PlatformOnlyOptions {
		if _, omit := IntentionalPublicOmissions[name]; omit {
			continue
		}
		out[name] = struct{}{}
	}
	return out
}

// MissingFeatureCompleteDefines returns -V feature names that are not #define'd.
func MissingFeatureCompleteDefines(versionText string) []string {
	var missing []string
	for _, name := range FeatureCompleteDefines {
		if !featureDefined(versionText, name) {
			missing = append(missing, name)
		}
	}
	return missing
}

func featureDefined(versionText, name string) bool {
	for _, line := range strings.Split(versionText, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#undef "+name) {
			return false
		}
		if line == "#define "+name || strings.HasPrefix(line, "#define "+name+" ") {
			return true
		}
	}
	return false
}
