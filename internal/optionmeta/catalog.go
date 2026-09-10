package optionmeta

import (
	"fmt"
	"slices"
	"strings"
)

var catalog = mustCatalog(slices.Concat(
	listenDefs,
	socketDefs,
	fileDefs,
	processDefs,
	transferDefs,
	tlsDefs,
	hiddenTLSDefs,
	tunDefs,
	getOnlyIPv4Defs,
	isolationDefs,
	termiosAliasDefs,
	hiddenMiscDefs,
))

var (
	bySpelling      map[string]int
	parserAliasMap  map[string]string
	isolationByName map[string]string
)

func mustCatalog(defs []Def) []Def {
	if err := validateCatalog(defs); err != nil {
		panic(err)
	}
	return defs
}

func init() {
	bySpelling = make(map[string]int, len(catalog)*3)
	parserAliasMap = make(map[string]string)
	isolationByName = make(map[string]string)
	for i, d := range catalog {
		for _, name := range d.Names() {
			bySpelling[name] = i
		}
		for _, alias := range d.ParseAliases() {
			parserAliasMap[alias] = d.Canonical
		}
		if d.Isolation {
			isolationByName[d.Canonical] = d.Canonical
			for _, alias := range d.ParseAliases() {
				isolationByName[alias] = d.Canonical
			}
		}
	}
}

func validateCatalog(defs []Def) error {
	seenCanonical := make(map[string]int, len(defs))
	seenSpelling := make(map[string]string)
	claim := func(name, canonical, kind string) error {
		if err := validateMetaName(name, kind); err != nil {
			return fmt.Errorf("%s: %w", canonical, err)
		}
		if owner, ok := seenSpelling[name]; ok {
			return fmt.Errorf("spelling %q claimed by %q and %q", name, owner, canonical)
		}
		seenSpelling[name] = canonical
		return nil
	}
	for i, d := range defs {
		if err := validateMetaName(d.Canonical, "canonical"); err != nil {
			return err
		}
		if _, ok := seenCanonical[d.Canonical]; ok {
			return fmt.Errorf("duplicate canonical name %q", d.Canonical)
		}
		seenCanonical[d.Canonical] = i
		if err := claim(d.Canonical, d.Canonical, "canonical"); err != nil {
			return err
		}
		if err := validateValueKind(d.Value); err != nil {
			return fmt.Errorf("%s: %w", d.Canonical, err)
		}
		if d.Help != HelpAdvertised && d.Help != HelpHidden {
			return fmt.Errorf("%s: unknown help visibility %d", d.Canonical, d.Help)
		}
		if d.Advertise & ^(AdvertiseLinux|AdvertiseDarwin|AdvertiseWindows) != 0 {
			return fmt.Errorf("%s: unknown help platform %d", d.Canonical, d.Advertise)
		}
		if !knownSection(d.Section, d.Help) {
			return fmt.Errorf("%s: unknown help section %q", d.Canonical, d.Section)
		}
		if d.Help == HelpAdvertised && d.Desc == "" && d.DynamicDesc == "" {
			return fmt.Errorf("%s: advertised option missing description", d.Canonical)
		}
		if !knownTypeSet(d.Apply.TypeSet) {
			return fmt.Errorf("%s: unknown type set %q", d.Canonical, d.Apply.TypeSet)
		}
		if !knownImplSet(d.Apply.ImplSet) {
			return fmt.Errorf("%s: unknown impl set %q", d.Canonical, d.Apply.ImplSet)
		}
		if d.Isolation && d.Help != HelpHidden {
			return fmt.Errorf("%s: isolation options are not advertised", d.Canonical)
		}
		if d.Kernel != "" && d.Help != HelpHidden {
			return fmt.Errorf("%s: get-only options are not advertised", d.Canonical)
		}
		for _, alias := range d.Names()[1:] {
			if err := claim(alias, d.Canonical, "alias"); err != nil {
				return err
			}
		}
	}
	return nil
}

// All returns a copy of the catalog.
func All() []Def {
	out := make([]Def, len(catalog))
	for i, d := range catalog {
		out[i] = copyDef(d)
	}
	return out
}

// Lookup finds an option by canonical name, parser alias, or public alias.
func Lookup(name string) (Def, bool) {
	i, ok := bySpelling[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return Def{}, false
	}
	return copyDef(catalog[i]), true
}

// ParserCanonical folds parser aliases. Public-only aliases are left unchanged.
func ParserCanonical(name string) string {
	n := strings.ToLower(name)
	if c, ok := parserAliasMap[n]; ok {
		return c
	}
	return n
}

// AdvertisedIn returns advertised options in one help section, catalog order.
func AdvertisedIn(section string) []Def {
	var out []Def
	for _, d := range catalog {
		if d.Help != HelpAdvertised || d.Section != section {
			continue
		}
		out = append(out, copyDef(d))
	}
	return out
}

// PublicTLSCanonicals are advertised TLS families rejected on plaintext PROXY.
func PublicTLSCanonicals() []string {
	var out []string
	for _, d := range catalog {
		if d.PublicTLS {
			out = append(out, d.Canonical)
		}
	}
	return out
}

// TLSRejectReasons maps canonical names to runtime TLS reject reasons.
func TLSRejectReasons() map[string]string {
	out := make(map[string]string)
	for _, d := range catalog {
		if d.TLSRejectReason == "" {
			continue
		}
		out[d.Canonical] = d.TLSRejectReason
	}
	return out
}

// IsolationCanonical reports whether name is a process-isolation option.
func IsolationCanonical(name string) (string, bool) {
	c, ok := isolationByName[strings.ToLower(strings.TrimSpace(name))]
	return c, ok
}

// IsPathValue reports whether the parser-canonical name is a filesystem path.
func IsPathValue(canonical string) bool {
	d, ok := Lookup(canonical)
	return ok && d.PathValue
}

// AncillaryCanonicals returns the IP ancillary families.
func AncillaryCanonicals() []string {
	var out []string
	for _, d := range catalog {
		if d.Ancillary {
			out = append(out, d.Canonical)
		}
	}
	return out
}
