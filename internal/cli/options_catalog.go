package cli

import (
	"fmt"
	"runtime"

	"github.com/oittaa/socat/internal/optionmeta"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func addressOptionFromDef(def optionmeta.Def) addressOption {
	caps := def.Apply.Caps
	if def.Apply.Unrestricted {
		caps = nil
	}
	return addressOption{
		validate:             validatorFor(def.Value),
		addressGroups:        def.Apply.AddressGroups,
		addressTypes:         expandTypeSet(def.Apply.TypeSet, def.Apply.AddressTypes),
		restrictAddressTypes: def.Apply.RestrictTypes,
		optionCaps:           caps,
		implementationGroups: expandImpl(def),
	}
}

func cliSpellings(def optionmeta.Def) []string {
	seen := map[string]struct{}{}
	var names []string
	add := func(name string) {
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	add(def.Canonical)
	for _, alias := range def.PublicAliases {
		add(alias)
	}
	for _, alias := range def.ParserAliases {
		add(alias)
	}
	return names
}

func expandTypeSet(set string, extra []string) []string {
	if len(extra) > 0 {
		return extra
	}
	switch set {
	case optionmeta.TypesTLS:
		return tlsAddressTypes()
	case optionmeta.TypesDTLS:
		return dtlsAddressTypes()
	case optionmeta.TypesALPN:
		return alpnAddressTypes()
	case optionmeta.TypesWS:
		return wsAddressTypes()
	case optionmeta.TypesProxy:
		return proxyAddressTypes()
	case optionmeta.TypesSocks:
		return socksAddressTypes()
	case optionmeta.TypesHandshake:
		return handshakeAddressTypes()
	case optionmeta.TypesFD:
		return fdOptionAddressTypes()
	case optionmeta.TypesBacklog:
		return backlogListenAddressTypes()
	case optionmeta.TypesResolver:
		return resolverAddressTypes()
	case optionmeta.TypesSocketTimeout:
		return socketTimeoutAddressTypes()
	case optionmeta.TypesTCPStream:
		return tcpStreamAddressTypes()
	default:
		return nil
	}
}

func expandImpl(def optionmeta.Def) []string {
	switch def.Apply.ImplSet {
	case optionmeta.ImplResolver:
		return resolverImplementationGroups()
	case optionmeta.ImplAncillary:
		return xio.IPAncillaryImplementationGroups(def.Canonical)
	default:
		return def.Apply.ImplGroups
	}
}

func validatorFor(kind optionmeta.ValueKind) func(parse.Option) error {
	switch kind {
	case optionmeta.ValueNone:
		return nil
	case optionmeta.RequiredString:
		return validateRequiredString
	case optionmeta.OptionalBool:
		return validateOptionalBool
	case optionmeta.OptionalSignedInteger:
		return validateOptionalSignedInteger
	case optionmeta.OptionalByte:
		return validateOptionalByte
	case optionmeta.OptionalInteger0:
		return validateOptionalInteger(0)
	case optionmeta.IntegerMin0:
		return validateInteger(0)
	case optionmeta.IntegerMin1:
		return validateInteger(1)
	case optionmeta.IntegerMinNeg1:
		return validateInteger(-1)
	case optionmeta.Duration:
		return validateDurationOption
	case optionmeta.Octal777:
		return validateOctal(0o777)
	case optionmeta.Octal7777:
		return validateOctal(0o7777)
	case optionmeta.SizeT:
		return validateSizeT
	case optionmeta.OptionalInt64:
		return validateOptionalInt64
	case optionmeta.Int64:
		return validateInt64(false)
	case optionmeta.PositiveInt64:
		return validateInt64(true)
	case optionmeta.IntegerRange0_2:
		return validateIntegerRange(0, 2)
	case optionmeta.IntegerRange256_65507:
		return validateIntegerRange(256, 65507)
	case optionmeta.ResNSAddr:
		return validateResNSAddr
	case optionmeta.NoValue:
		return validateNoValue
	case optionmeta.Shut:
		return validateShutOption
	case optionmeta.SockoptBin:
		return validateSockoptBin
	case optionmeta.SockoptInt:
		return validateSockoptInt
	case optionmeta.SockoptString:
		return validateSockoptString
	case optionmeta.GenericIoctl:
		return xio.ValidateGenericIoctl
	case optionmeta.UnixTightSocklen:
		return validateUnixTightSocklen
	default:
		panic(fmt.Sprintf("unknown option value kind %d", kind))
	}
}

func validateUnixTightSocklen(option parse.Option) error {
	if err := validateOptionalBool(option); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return fmt.Errorf("%s: not supported on this platform", option.Name)
	}
	return nil
}
