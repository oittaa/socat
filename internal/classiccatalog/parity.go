package classiccatalog

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Option and address parity classification for classic socat
// (https://repo.or.cz/socat.git tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a has the same doc/socat.yo and
// option/address help). RequiredPublicSpellings is the public interface.
// ClassifyOption splits that set so CI can pin expected gaps without treating
// security exclusions or foreign-OS names as an implementation backlog.
//
// Expected-missing maps are split by family so later compatibility PRs edit
// only the file they implement.

// Platforms is a bit set of GOOS values this port tests (linux, darwin, windows).
// Other Unix GOOS values use the darwin bit (same help gating as help_unix_other.go).
type Platforms uint8

const (
	PlatLinux Platforms = 1 << iota
	PlatDarwin
	PlatWindows
	PlatUnix           = PlatLinux | PlatDarwin
	PlatAll            = PlatLinux | PlatDarwin | PlatWindows
	PlatNone Platforms = 0
)

// Has reports whether goos is one of the platforms in p.
func (p Platforms) Has(goos string) bool {
	return p&platformBit(goos) != 0
}

func platformBit(goos string) Platforms {
	switch goos {
	case "linux":
		return PlatLinux
	case "windows":
		return PlatWindows
	default:
		return PlatDarwin
	}
}

// Gap is one classified public spelling that this build does not advertise.
type Gap struct {
	Reason    string
	Platforms Platforms
}

// OptionClass is how one public option spelling is treated on a GOOS.
type OptionClass int

const (
	// ClassMustAdvertise: implemented on this GOOS; -hhh must list it unless
	// the help table already hides it on this platform.
	ClassMustAdvertise OptionClass = iota
	// ClassExpectedMissing: target-platform work still to implement.
	ClassExpectedMissing
	// ClassUnsupported: documented and intentionally rejected; never advertise;
	// not an implementation backlog item.
	ClassUnsupported
	// ClassForeign: not applicable on this GOOS (other-OS or never-on-targets).
	ClassForeign
	// ClassOptionalParserOnly: undocumented C parser alias; not required.
	ClassOptionalParserOnly
)

func (c OptionClass) String() string {
	switch c {
	case ClassMustAdvertise:
		return "must-advertise"
	case ClassExpectedMissing:
		return "expected-missing"
	case ClassUnsupported:
		return "unsupported"
	case ClassForeign:
		return "foreign"
	case ClassOptionalParserOnly:
		return "parser-only"
	default:
		return fmt.Sprintf("option-class(%d)", int(c))
	}
}

// AddressClass is how one classic address keyword is treated on a GOOS.
type AddressClass int

const (
	// AddrMustRegister: canonical or already-registered alias; opener must exist.
	AddrMustRegister AddressClass = iota
	// AddrExpectedMissingCanonical: canonical address not yet implemented.
	AddrExpectedMissingCanonical
	// AddrExpectedMissingAlias: alias of an implemented canonical (PR C).
	AddrExpectedMissingAlias
	// AddrUnsupportedFamily: DCCP, DTLS, or readline.
	AddrUnsupportedFamily
	// AddrParserShorthand: "-" → STDIO in the parser, not the address registry.
	AddrParserShorthand
	// AddrForeign: canonical not applicable on this GOOS.
	AddrForeign
)

func (c AddressClass) String() string {
	switch c {
	case AddrMustRegister:
		return "must-register"
	case AddrExpectedMissingCanonical:
		return "expected-missing-canonical"
	case AddrExpectedMissingAlias:
		return "expected-missing-alias"
	case AddrUnsupportedFamily:
		return "unsupported-family"
	case AddrParserShorthand:
		return "parser-shorthand"
	case AddrForeign:
		return "foreign"
	default:
		return fmt.Sprintf("address-class(%d)", int(c))
	}
}

var (
	expectedOnce sync.Once
	expectedAll  map[string]Gap
	expectedErr  error

	unsupportedOnce sync.Once
	unsupportedAll  map[string]string
	unsupportedErr  error
)

func expectedMissingSources() []map[string]Gap {
	return []map[string]Gap{
		expectedMissingAppl,
		expectedMissingExec,
		expectedMissingFD,
		expectedMissingHTTP,
		expectedMissingIOCTL,
		expectedMissingIP,
		expectedMissingIP6,
		expectedMissingInterface,
		expectedMissingOpen,
		expectedMissingParent,
		expectedMissingProcess,
		expectedMissingPTY,
		expectedMissingReg,
		expectedMissingResolver,
		expectedMissingSCTP,
		expectedMissingSocket,
		expectedMissingTCP,
		expectedMissingTCPBSD,
		expectedMissingUDP,
		expectedMissingUNIX,
	}
}

func unsupportedSources() []map[string]string {
	return []map[string]string{
		IntentionalPublicOmissions,
		unsupportedOpenSSL,
		unsupportedReadline,
		unsupportedDCCP,
		unsupportedNoopSockopts,
	}
}

func mergeExpectedMissing() (map[string]Gap, error) {
	out := make(map[string]Gap)
	var dups []string
	var empty []string
	for _, src := range expectedMissingSources() {
		for name, gap := range src {
			if gap.Reason == "" {
				empty = append(empty, name)
			}
			if _, ok := out[name]; ok {
				dups = append(dups, name)
				continue
			}
			out[name] = gap
		}
	}
	sort.Strings(dups)
	sort.Strings(empty)
	if len(dups) > 0 {
		return out, fmt.Errorf("duplicate expected-missing option %s", strings.Join(dups, ", "))
	}
	if len(empty) > 0 {
		return out, fmt.Errorf("expected-missing option without a reason: %s", strings.Join(empty, ", "))
	}
	return out, nil
}

func mergeUnsupported() (map[string]string, error) {
	out := make(map[string]string)
	var dups []string
	var empty []string
	for _, src := range unsupportedSources() {
		for name, reason := range src {
			if reason == "" {
				empty = append(empty, name)
			}
			if prev, ok := out[name]; ok && prev != reason {
				dups = append(dups, name)
				continue
			}
			out[name] = reason
		}
	}
	sort.Strings(dups)
	sort.Strings(empty)
	if len(dups) > 0 {
		return out, fmt.Errorf("duplicate unsupported option %s", strings.Join(dups, ", "))
	}
	if len(empty) > 0 {
		return out, fmt.Errorf("unsupported option without a reason: %s", strings.Join(empty, ", "))
	}
	return out, nil
}

func expectedMissingMerged() map[string]Gap {
	expectedOnce.Do(func() {
		expectedAll, expectedErr = mergeExpectedMissing()
	})
	return expectedAll
}

func unsupportedMerged() map[string]string {
	unsupportedOnce.Do(func() {
		unsupportedAll, unsupportedErr = mergeUnsupported()
	})
	return unsupportedAll
}

// ExpectedMissingAll is every expected-missing option spelling, including
// names that are only a backlog on some GOOS values.
func ExpectedMissingAll() map[string]Gap {
	src := expectedMissingMerged()
	out := make(map[string]Gap, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// UnsupportedPublic is documented public spellings this port must not
// advertise and must not list as implementation backlog. It includes
// IntentionalPublicOmissions plus OpenSSL/readline/DCCP/no-op exclusions.
func UnsupportedPublic() map[string]string {
	src := unsupportedMerged()
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// ForeignPublic is documented spellings that are never a requirement on
// linux, darwin, or windows (HP-UX, OSF1, STREAMS, and similar).
func ForeignPublic() map[string]Gap {
	out := make(map[string]Gap, len(foreignPublic))
	for k, v := range foreignPublic {
		out[k] = v
	}
	return out
}

// ImplementationBacklog is expected-missing option spellings for goos.
// Unsupported and foreign-on-this-GOOS names are omitted.
func ImplementationBacklog(goos string) map[string]string {
	out := make(map[string]string)
	for name, gap := range expectedMissingMerged() {
		if gap.Platforms.Has(goos) {
			out[name] = gap.Reason
		}
	}
	return out
}

// ClassifyOption returns the parity class of a public option spelling on goos.
func ClassifyOption(name, goos string) (OptionClass, string) {
	name = strings.ToLower(name)
	if reason, ok := OptionalParserOnlyAliases[name]; ok {
		return ClassOptionalParserOnly, reason
	}
	if reason, ok := unsupportedMerged()[name]; ok {
		return ClassUnsupported, reason
	}
	if gap, ok := expectedMissingMerged()[name]; ok {
		if gap.Platforms.Has(goos) {
			return ClassExpectedMissing, gap.Reason
		}
		return ClassForeign, gap.Reason
	}
	if gap, ok := foreignPublic[name]; ok {
		if gap.Platforms != PlatNone && gap.Platforms.Has(goos) {
			return ClassExpectedMissing, gap.Reason
		}
		return ClassForeign, gap.Reason
	}
	return ClassMustAdvertise, ""
}

// ClassifyAddress returns the parity class of a classic address keyword on goos.
func ClassifyAddress(name, goos string) (AddressClass, string) {
	name = strings.ToUpper(strings.TrimSpace(name))
	if canon, ok := ParserAddressShorthands[name]; ok {
		return AddrParserShorthand, "parser shorthand for " + canon
	}
	if reason, ok := UnsupportedAddressNames[name]; ok {
		return AddrUnsupportedFamily, reason
	}
	if gap, ok := ExpectedMissingCanonicalAddresses[name]; ok {
		if gap.Platforms.Has(goos) {
			return AddrExpectedMissingCanonical, gap.Reason
		}
		return AddrForeign, gap.Reason
	}
	if canon, ok := ExpectedMissingAddressAliases[name]; ok {
		return AddrExpectedMissingAlias, "alias of implemented " + canon
	}
	return AddrMustRegister, ""
}

// ValidateParityManifests reports classification-table errors (duplicates,
// empty reasons, overlaps, names that are not public, implemented-vs-missing
// is checked against -hhh in the CLI audit).
func ValidateParityManifests() error {
	expectedMissingMerged()
	unsupportedMerged()
	if expectedErr != nil {
		return expectedErr
	}
	if unsupportedErr != nil {
		return unsupportedErr
	}
	var errs []string
	seen := map[string]string{}
	check := func(name, bucket string) {
		if prev, ok := seen[name]; ok && prev != bucket {
			errs = append(errs, fmt.Sprintf("%q is in both %s and %s", name, prev, bucket))
		}
		seen[name] = bucket
	}
	for name, gap := range expectedMissingMerged() {
		if gap.Reason == "" {
			errs = append(errs, "expected-missing "+name+" has no reason")
		}
		if !knownPublicSpelling(name) {
			errs = append(errs, "expected-missing "+name+" is not a public classic spelling")
		}
		check(name, "expected-missing")
	}
	for name, reason := range unsupportedMerged() {
		if reason == "" {
			errs = append(errs, "unsupported "+name+" has no reason")
		}
		if !knownPublicSpelling(name) {
			errs = append(errs, "unsupported "+name+" is not a public classic spelling")
		}
		check(name, "unsupported")
	}
	for name, gap := range foreignPublic {
		if gap.Reason == "" {
			errs = append(errs, "foreign "+name+" has no reason")
		}
		if !knownPublicSpelling(name) {
			errs = append(errs, "foreign "+name+" is not a public classic spelling")
		}
		check(name, "foreign")
	}
	for name := range OptionalParserOnlyAliases {
		if _, ok := expectedMissingMerged()[name]; ok {
			errs = append(errs, "parser-only alias "+name+" must not be expected-missing")
		}
		if _, ok := RequiredPublicSpellings()[name]; ok {
			errs = append(errs, "parser-only alias "+name+" must not be a required public spelling")
		}
	}
	for name := range DocsOnlyNotInThisBinary {
		class, _ := ClassifyOption(name, "linux")
		switch class {
		case ClassExpectedMissing, ClassUnsupported, ClassForeign, ClassOptionalParserOnly:
		default:
			// Docs-only names are never advertised by the Linux reference
			// binary, so they cannot be ClassMustAdvertise without a map entry.
			errs = append(errs, "docs-only "+name+" is not classified (expected-missing, unsupported, or foreign)")
		}
	}
	if err := validateAddressManifests(); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) == 0 {
		return nil
	}
	sort.Strings(errs)
	return fmt.Errorf("parity manifests:\n  %s", strings.Join(errs, "\n  "))
}

func knownPublicSpelling(name string) bool {
	if _, ok := Options[name]; ok {
		return true
	}
	if _, ok := DocsOnlyNotInThisBinary[name]; ok {
		return true
	}
	if _, ok := OptionalParserOnlyAliases[name]; ok {
		return true
	}
	return false
}

func validateAddressManifests() error {
	var errs []string
	seen := map[string]string{}
	check := func(name, bucket string) {
		name = strings.ToUpper(name)
		if prev, ok := seen[name]; ok && prev != bucket {
			errs = append(errs, fmt.Sprintf("address %q is in both %s and %s", name, prev, bucket))
		}
		seen[name] = bucket
	}
	for name, gap := range ExpectedMissingCanonicalAddresses {
		if gap.Reason == "" {
			errs = append(errs, "expected-missing canonical address "+name+" has no reason")
		}
		check(name, "missing-canonical")
	}
	for name, canon := range ExpectedMissingAddressAliases {
		if canon == "" {
			errs = append(errs, "expected-missing address alias "+name+" has no canonical")
		}
		if _, ok := ExpectedMissingCanonicalAddresses[canon]; ok {
			errs = append(errs, "address alias "+name+" points at unimplemented "+canon+"; keep it out of the supported-alias backlog")
		}
		if _, ok := UnsupportedAddressNames[name]; ok {
			errs = append(errs, "address alias "+name+" is also listed as an unsupported family")
		}
		check(name, "missing-alias")
	}
	for name, reason := range UnsupportedAddressNames {
		if reason == "" {
			errs = append(errs, "unsupported address "+name+" has no reason")
		}
		check(name, "unsupported")
	}
	for name, canon := range ParserAddressShorthands {
		if canon == "" {
			errs = append(errs, "parser shorthand "+name+" has no canonical")
		}
		check(name, "parser")
	}
	if len(errs) == 0 {
		return nil
	}
	sort.Strings(errs)
	return fmt.Errorf("%s", strings.Join(errs, "; "))
}
