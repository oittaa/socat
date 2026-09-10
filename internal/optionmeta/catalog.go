package optionmeta

import (
	"fmt"
	"strings"
)

// Section groups options for help. Its title never controls address acceptance.
type Section struct {
	Title   string
	Options []Option
}

var sections = []Section{
	{SectionListen, listenOptions},
	{SectionSecurity, securityOptions},
	{SectionSockets, socketOptions},
	{SectionFiles, fileOptions},
	{SectionExec, processOptions},
	{SectionPTY, terminalOptions},
	{SectionTransfer, transferOptions},
	{SectionTLS, tlsOptions},
	{SectionDTLS, dtlsOptions},
	{SectionWebSocket, webSocketOptions},
	{SectionProxy, proxyOptions},
	{SectionPOSIXMQ, posixMQOptions},
	{SectionTUN, tunOptions},
	{SectionNamespaces, namespaceOptions},
}

var catalog = func() []Option {
	var all []Option
	for _, section := range sections {
		all = append(all, section.Options...)
	}
	for _, hidden := range [][]Option{hiddenTLSOptions, getOnlyIPv4Options, isolationOptions, terminalAliases, rejectedIPv6Options} {
		all = append(all, hidden...)
	}
	return all
}()

var bySpelling = make(map[string]int)
var parserAliases = make(map[string]string)

func init() {
	if err := validateCatalog(catalog); err != nil {
		panic(err)
	}
	for i, d := range catalog {
		for _, name := range d.Names() {
			bySpelling[name] = i
		}
		for _, alias := range d.ParseAliases() {
			parserAliases[alias] = d.Canonical
		}
	}
}

func validateCatalog(defs []Option) error {
	seen := make(map[string]string)
	for _, d := range defs {
		for _, name := range d.Names() {
			if name == "" || name != strings.ToLower(name) {
				return fmt.Errorf("invalid option spelling %q", name)
			}
			if owner, exists := seen[name]; exists {
				return fmt.Errorf("spelling %q claimed by %q and %q", name, owner, d.Canonical)
			}
			seen[name] = d.Canonical
		}
	}
	return nil
}

// Sections returns the help sections and their options in display order.
func Sections() []Section {
	out := make([]Section, len(sections))
	for i, section := range sections {
		out[i] = Section{Title: section.Title, Options: make([]Option, len(section.Options))}
		for j, d := range section.Options {
			out[i].Options[j] = cloneOption(d)
		}
	}
	return out
}

// Lookup finds any recognized spelling without changing its parser meaning.
func Lookup(name string) (Option, bool) {
	i, ok := bySpelling[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return Option{}, false
	}
	return cloneOption(catalog[i]), true
}

// ParserCanonical folds parser aliases. Public-only aliases remain unchanged.
func ParserCanonical(name string) string {
	name = strings.ToLower(name)
	if canonical, ok := parserAliases[name]; ok {
		return canonical
	}
	return name
}

// IsolationCanonical identifies an option rejected by process-isolation policy.
func IsolationCanonical(name string) (string, bool) {
	d, ok := Lookup(name)
	return d.Canonical, ok && d.Isolation
}

// IsPathValue identifies values whose Windows path separators must be preserved.
func IsPathValue(name string) bool {
	d, ok := Lookup(name)
	return ok && d.PathValue
}
