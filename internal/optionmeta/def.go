// Package optionmeta holds option identity shared by the parser, CLI, and
// runtime. Family files declare names, aliases, help visibility, value
// contracts, and applicability. Specialized validators, termios syscall
// tables, and IP-ancillary kernel effects stay with their owning code.
package optionmeta

import (
	"fmt"
	"strings"
)

// ValueKind selects the CLI validator. Implementations live in the CLI
// (and ioctl in xio). Zero means no dedicated validator.
type ValueKind uint8

const (
	ValueNone ValueKind = iota
	RequiredString
	OptionalBool
	OptionalSignedInteger
	OptionalByte
	OptionalInteger0
	IntegerMin0
	IntegerMin1
	IntegerMinNeg1
	Duration
	Octal777
	Octal7777
	SizeT
	OptionalInt64
	Int64
	PositiveInt64
	IntegerRange0_2
	IntegerRange256_65507
	ResNSAddr
	NoValue
	Shut
	SockoptBin
	SockoptInt
	SockoptString
	GenericIoctl
	UnixTightSocklen
)

// HelpVisibility is whether -hh/-hhh lists the option.
type HelpVisibility uint8

const (
	HelpAdvertised HelpVisibility = iota
	HelpHidden
)

// AdvertiseOn selects the supported platforms that list an option in help.
type AdvertiseOn uint8

const (
	AdvertiseAll         AdvertiseOn = 0
	AdvertiseLinux       AdvertiseOn = 1 << 0
	AdvertiseDarwin      AdvertiseOn = 1 << 1
	AdvertiseWindows     AdvertiseOn = 1 << 2
	AdvertiseLinuxDarwin             = AdvertiseLinux | AdvertiseDarwin
)

// Applicability is which addresses may take an option. It is independent of
// help section titles.
type Applicability struct {
	Caps          []string
	Unrestricted  bool
	AddressGroups []string
	AddressTypes  []string
	TypeSet       string
	RestrictTypes bool
	ImplGroups    []string
	ImplSet       string
}

// Def describes one option. Aliases both fold and appear in help;
// ParserAliases and PublicAliases are exceptions with only one of those roles.
type Def struct {
	Canonical       string
	Aliases         []string
	ParserAliases   []string
	PublicAliases   []string
	Help            HelpVisibility
	Section         string
	Desc            string
	DynamicDesc     string
	Value           ValueKind
	Apply           Applicability
	Advertise       AdvertiseOn
	TLSRejectReason string
	Kernel          string
	Isolation       bool
	PublicTLS       bool
	PathValue       bool
	Ancillary       bool
}

func validateMetaName(name, kind string) error {
	if name == "" {
		return fmt.Errorf("empty %s name", kind)
	}
	if name != strings.ToLower(name) {
		return fmt.Errorf("non-lowercase %s name %q", kind, name)
	}
	return nil
}

func validateValueKind(kind ValueKind) error {
	switch kind {
	case ValueNone, RequiredString, OptionalBool, OptionalSignedInteger,
		OptionalByte, OptionalInteger0, IntegerMin0, IntegerMin1, IntegerMinNeg1,
		Duration, Octal777, Octal7777, SizeT, OptionalInt64, Int64, PositiveInt64,
		IntegerRange0_2, IntegerRange256_65507, ResNSAddr, NoValue, Shut,
		SockoptBin, SockoptInt, SockoptString, GenericIoctl, UnixTightSocklen:
		return nil
	default:
		return fmt.Errorf("unknown value kind %d", kind)
	}
}

func copyStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	return append([]string(nil), in...)
}

func copyDef(d Def) Def {
	d.Aliases = copyStrings(d.Aliases)
	d.ParserAliases = copyStrings(d.ParserAliases)
	d.PublicAliases = copyStrings(d.PublicAliases)
	d.Apply.Caps = copyStrings(d.Apply.Caps)
	d.Apply.AddressGroups = copyStrings(d.Apply.AddressGroups)
	d.Apply.AddressTypes = copyStrings(d.Apply.AddressTypes)
	d.Apply.ImplGroups = copyStrings(d.Apply.ImplGroups)
	return d
}

// Hidden reports whether the current build omits this option from help.
func Hidden(d Def) bool {
	return d.Advertise != AdvertiseAll && d.Advertise&currentPlatform == 0
}

// ParseAliases returns every spelling that folds onto the canonical name.
func (d Def) ParseAliases() []string {
	return append(copyStrings(d.Aliases), d.ParserAliases...)
}

// HelpAliases returns the aliases advertised with this option.
func (d Def) HelpAliases() []string {
	return append(copyStrings(d.Aliases), d.PublicAliases...)
}

// Names returns each recognized spelling once, including the canonical name.
func (d Def) Names() []string {
	names := make([]string, 0, 1+len(d.Aliases)+len(d.ParserAliases)+len(d.PublicAliases))
	names = append(names, d.Canonical)
	names = append(names, d.Aliases...)
	names = append(names, d.ParserAliases...)
	return append(names, d.PublicAliases...)
}

func knownTypeSet(set string) bool {
	switch set {
	case "", TypesTLS, TypesDTLS, TypesALPN, TypesWS, TypesProxy, TypesSocks,
		TypesHandshake, TypesFD, TypesBacklog, TypesResolver, TypesSocketTimeout,
		TypesTCPStream:
		return true
	default:
		return false
	}
}

func knownImplSet(set string) bool {
	switch set {
	case "", ImplResolver, ImplAncillary:
		return true
	default:
		return false
	}
}

func knownSection(section string, help HelpVisibility) bool {
	if help == HelpHidden {
		return section == ""
	}
	switch section {
	case SectionListen, SectionSecurity, SectionSockets, SectionFiles,
		SectionExec, SectionPTY, SectionTransfer, SectionTLS, SectionDTLS,
		SectionWebSocket, SectionProxy, SectionPOSIXMQ, SectionTUN,
		SectionNamespaces:
		return true
	default:
		return false
	}
}
