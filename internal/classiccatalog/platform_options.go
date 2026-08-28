package classiccatalog

// PlatformOption records a spelling that is absent from the Linux reference
// dump but is printed by classic -hhh when its host defines the option.
type PlatformOption struct {
	Entry
	Platforms Platforms
	Reason    string
}

// PlatformOnlyOptions comes from the official classic optionnames[] table at
// tag-1.8.1.3 (12c08bf66d709fba17035ce95d85bd218428d9ba). Official master
// af5388c898c7bb60997935aee93c223deba60c4a is identical. O_BINARY, O_TEXT,
// and O_NOINHERIT are absent from the Linux fixture but present on Cygwin, so
// both the documented names and the aliases printed by that binary are public.
var PlatformOnlyOptions = map[string]PlatformOption{
	"bin": {
		Entry:     Entry{Spelling: "bin", Canonical: "binary", Groups: []string{"FD", "OPEN"}, Phase: "OPEN", Type: "BOOL"},
		Platforms: PlatWindows, Reason: "classic advertises this O_BINARY alias on Cygwin",
	},
	"binary": {
		Entry:     Entry{Spelling: "binary", Canonical: "binary", Groups: []string{"FD", "OPEN"}, Phase: "OPEN", Type: "BOOL"},
		Platforms: PlatWindows, Reason: "documented O_BINARY option; classic advertises it on Cygwin",
	},
	"o-binary": {
		Entry:     Entry{Spelling: "o-binary", Canonical: "binary", Groups: []string{"FD", "OPEN"}, Phase: "OPEN", Type: "BOOL"},
		Platforms: PlatWindows, Reason: "classic advertises this O_BINARY alias on Cygwin",
	},
	"text": {
		Entry:     Entry{Spelling: "text", Canonical: "text", Groups: []string{"FD", "OPEN"}, Phase: "OPEN", Type: "BOOL"},
		Platforms: PlatWindows, Reason: "documented O_TEXT option; classic advertises it on Cygwin",
	},
	"o-text": {
		Entry:     Entry{Spelling: "o-text", Canonical: "text", Groups: []string{"FD", "OPEN"}, Phase: "OPEN", Type: "BOOL"},
		Platforms: PlatWindows, Reason: "classic advertises this O_TEXT alias on Cygwin",
	},
	"noinherit": {
		Entry:     Entry{Spelling: "noinherit", Canonical: "noinherit", Groups: []string{"FD", "OPEN"}, Phase: "OPEN", Type: "BOOL"},
		Platforms: PlatWindows, Reason: "documented O_NOINHERIT option; classic advertises it on Cygwin",
	},
	"o-noinherit": {
		Entry:     Entry{Spelling: "o-noinherit", Canonical: "noinherit", Groups: []string{"FD", "OPEN"}, Phase: "OPEN", Type: "BOOL"},
		Platforms: PlatWindows, Reason: "classic advertises this O_NOINHERIT alias on Cygwin",
	},
}
