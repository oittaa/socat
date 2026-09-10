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

// CLIValueKind is the historical name used by hidden TLS entries.
type CLIValueKind = ValueKind

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

// AdvertiseOn is which GOOS values list the option in help.
type AdvertiseOn uint8

const (
	AdvertiseAll AdvertiseOn = iota
	AdvertiseLinux
	AdvertiseDarwin
	AdvertiseWindows
	AdvertiseLinuxDarwin
	AdvertiseLinuxWindows
	AdvertiseDarwinWindows
	AdvertiseNone
)

// PlatformClass is a named hide-test category. Help still uses AdvertiseOn;
// these tags preserve the existing per-family hide helpers.
type PlatformClass uint8

const (
	PlatformNone PlatformClass = iota
	PlatformDarwinIPRecv
	PlatformLinuxRemainingIPv4
	PlatformLinuxIPv6RecvExt
	PlatformLinuxRecvErr
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

// Def is one option family: identity, aliases, help, value contract, and
// applicability. ParserAliases fold at parse time. PublicAliases are listed
// in -hhh and recognized by CLI spelling lookup; they need not be parser
// aliases. Runtime switches may still match public spellings that do not fold.
type Def struct {
	Canonical       string
	ParserAliases   []string
	PublicAliases   []string
	Help            HelpVisibility
	Section         string
	Desc            string
	DynamicDesc     string
	Value           ValueKind
	Apply           Applicability
	Advertise       AdvertiseOn
	Platform        PlatformClass
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
	d.ParserAliases = copyStrings(d.ParserAliases)
	d.PublicAliases = copyStrings(d.PublicAliases)
	d.Apply.Caps = copyStrings(d.Apply.Caps)
	d.Apply.AddressGroups = copyStrings(d.Apply.AddressGroups)
	d.Apply.AddressTypes = copyStrings(d.Apply.AddressTypes)
	d.Apply.ImplGroups = copyStrings(d.Apply.ImplGroups)
	return d
}

// HiddenOn reports whether help should omit this option on goos.
func HiddenOn(d Def, goos string) bool {
	switch d.Advertise {
	case AdvertiseAll:
		return false
	case AdvertiseLinux:
		return goos != "linux"
	case AdvertiseDarwin:
		return goos != "darwin"
	case AdvertiseWindows:
		return goos != "windows"
	case AdvertiseLinuxDarwin:
		return goos != "linux" && goos != "darwin"
	case AdvertiseLinuxWindows:
		return goos != "linux" && goos != "windows"
	case AdvertiseDarwinWindows:
		return goos != "darwin" && goos != "windows"
	case AdvertiseNone:
		return true
	default:
		return false
	}
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
