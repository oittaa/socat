package optionmeta

import "slices"

// Option is an option's shared identity and CLI contract. Runtime effects stay in xio.
type Option struct {
	Canonical       string
	Aliases         []string // Fold during parsing and appear in help.
	ParserAliases   []string // Fold during parsing; omitted from help.
	PublicAliases   []string // Appear in help; do not fold during parsing.
	Desc            string
	Scope           AddressScope
	Advertise       AdvertiseOn
	Hidden          bool
	PathValue       bool
	Isolation       bool
	PublicTLS       bool   // Rejected on plaintext PROXY transports.
	TLSRejectReason string // Reason crypto/tls cannot apply this option.
	Kernel          string // Get-only IPv4 option named in rejection diagnostics.
}

// AddressScope describes CLI acceptance, not whether an opener applied an option.
// Caps are alternatives. AddressTypes takes precedence over AddressGroups as an
// additional allowance. RestrictTypes and ImplGroups impose hard restrictions.
type AddressScope struct {
	Caps          []string
	AddressGroups []string
	AddressTypes  []string
	RestrictTypes bool
	ImplGroups    []string
}

type AdvertiseOn uint8

const (
	AdvertiseAll         AdvertiseOn = 0
	AdvertiseLinux       AdvertiseOn = 1 << 0
	AdvertiseDarwin      AdvertiseOn = 1 << 1
	AdvertiseWindows     AdvertiseOn = 1 << 2
	AdvertiseLinuxDarwin             = AdvertiseLinux | AdvertiseDarwin
)

// Visible reports whether this build advertises the option in help.
func (d Option) Visible() bool {
	return !d.Hidden && (d.Advertise == AdvertiseAll || d.Advertise&currentPlatform != 0)
}

func cloneOption(d Option) Option {
	d.Aliases = slices.Clone(d.Aliases)
	d.ParserAliases = slices.Clone(d.ParserAliases)
	d.PublicAliases = slices.Clone(d.PublicAliases)
	d.Scope.Caps = slices.Clone(d.Scope.Caps)
	d.Scope.AddressGroups = slices.Clone(d.Scope.AddressGroups)
	d.Scope.AddressTypes = slices.Clone(d.Scope.AddressTypes)
	d.Scope.ImplGroups = slices.Clone(d.Scope.ImplGroups)
	return d
}

// ParseAliases returns every alias that folds onto the canonical name.
func (d Option) ParseAliases() []string {
	return slices.Concat(d.Aliases, d.ParserAliases)
}

// HelpAliases returns the aliases advertised with this option.
func (d Option) HelpAliases() []string {
	return slices.Concat(d.Aliases, d.PublicAliases)
}

// Names returns every recognized spelling, including the canonical name.
func (d Option) Names() []string {
	return slices.Concat([]string{d.Canonical}, d.Aliases, d.ParserAliases, d.PublicAliases)
}
