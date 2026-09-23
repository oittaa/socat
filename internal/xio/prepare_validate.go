package xio

import (
	"fmt"
	"slices"
	"strings"
	"syscall"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/optionmeta"
	"github.com/oittaa/socat/internal/parse"
)

type resolvedAddressOptions struct {
	definitions   []optionmeta.Option
	scopeError    error
	platformError error
}

func resolveAddressOptions(spec parse.Spec, desc AddressDesc, registered bool) (resolvedAddressOptions, error) {
	resolved := resolvedAddressOptions{definitions: make([]optionmeta.Option, len(spec.Options))}
	reg := registrationSnapshot(desc)
	for i, option := range spec.Options {
		optionSpec, ok := lookupAddressOption(option)
		if !ok {
			return resolvedAddressOptions{}, fmt.Errorf("%s: unknown option %q", spec.Type, option.Name)
		}
		resolved.definitions[i] = optionSpec
		if resolved.platformError == nil && !optionSpec.Supported() {
			resolved.platformError = fmt.Errorf("%s: option %q is not supported on this platform", spec.Type, option.Name)
		}
		if !registered {
			continue
		}
		if !optionImplementedForGroup(desc.Group, optionSpec) {
			return resolvedAddressOptions{}, fmt.Errorf("%s: option %q not supported with this address type", spec.Type, option.Name)
		}
		s := optionSpec.Scope
		if resolved.scopeError == nil &&
			(!optionSupportedOnAddress(reg, s.AddressGroups, s.AddressTypes, s.Caps) ||
				s.RestrictTypes && !addressTypeAllowed(desc.Name, s.AddressTypes)) {
			resolved.scopeError = fmt.Errorf("%s: option %q not supported with this address type", spec.Type, option.Name)
		}
	}
	return resolved, nil
}

func rejectPreparedStaticChecks(config addrconfig.Address) error {
	if err := rejectUnsupportedIPAncillary(config); err != nil {
		return err
	}
	if err := rejectUnsupportedTermios(config); err != nil {
		return err
	}
	if err := rejectUnsupportedRecvErr(config); err != nil {
		return err
	}
	if err := validateDescriptorModeOptions(config); err != nil {
		return err
	}
	if err := rejectUnsupportedListenBacklog(config); err != nil {
		return err
	}
	if err := RejectUnsupportedUnixTightSocklen(config); err != nil {
		return err
	}
	if err := rejectUnusableProtocolFamily(config); err != nil {
		return err
	}
	return rejectPreparedSocketType(config)
}

// rejectUnusableProtocolFamily fails when pf= is not a family this address
// passes to socket() or getaddrinfo. SOCKET and VSOCK keep any number.
// IP addresses pass AF_UNSPEC, AF_INET, and AF_INET6. UNIX, abstract, exec,
// and SOCKETPAIR pass AF_UNIX. INTERFACE passes AF_PACKET. TUN passes AF_INET.
func rejectUnusableProtocolFamily(config addrconfig.Address) error {
	n := config.Network
	if !n.ProtocolSet || protocolFamilyPassed(config, n.ProtocolFamily) {
		return nil
	}
	return fmt.Errorf("%s: protocol family %d is not usable", config.Type, n.ProtocolFamily)
}

func protocolFamilyPassed(config addrconfig.Address, pf int) bool {
	switch config.Facts.Kind {
	case addrconfig.AddressKindSocket, addrconfig.AddressKindVSOCK:
		return true
	case addrconfig.AddressKindUNIX, addrconfig.AddressKindABSTRACT,
		addrconfig.AddressKindEXEC, addrconfig.AddressKindSYSTEM, addrconfig.AddressKindSHELL:
		return pf == syscall.AF_UNIX
	case addrconfig.AddressKindINTERFACE:
		return interfaceProtocolFamily(pf)
	case addrconfig.AddressKindTUN:
		return pf == syscall.AF_INET
	}
	if config.Type == "SOCKETPAIR" {
		return pf == syscall.AF_UNIX
	}
	if passesIPProtocolFamily(config.Facts.Group) {
		return pf == syscall.AF_UNSPEC || pf == syscall.AF_INET || pf == syscall.AF_INET6
	}
	return false
}

func passesIPProtocolFamily(group string) bool {
	switch group {
	case GroupTCP, GroupUDP, GroupSCTP, GroupRawIP, GroupTLS, GroupDTLS, GroupWebSocket, GroupQUIC, GroupProxy:
		return true
	default:
		return false
	}
}

func rejectPreparedSocketType(config addrconfig.Address) error {
	if !config.Network.SocketType.Set {
		return nil
	}
	_, _, err := configuredSocketType(config, config.Type, 0)
	return err
}

func lookupAddressOption(option parse.Option) (optionmeta.Option, bool) {
	for _, name := range []string{option.OriginalSpelling(), option.Name} {
		if def, ok := optionmeta.Lookup(name); ok {
			return def, true
		}
		if isTermiosOption(name) {
			canonical := strings.ToLower(strings.TrimSpace(option.Name))
			if canonical == "" {
				canonical = strings.ToLower(strings.TrimSpace(name))
			}
			return optionmeta.Option{
				Canonical: canonical,
				Kind:      addrconfig.TermiosValueKind(canonical),
				Scope:     optionmeta.AddressScope{Caps: []string{capTermios}},
			}, true
		}
	}
	return optionmeta.Option{}, false
}

func optionImplementedForGroup(group string, option optionmeta.Option) bool {
	if !ipAncillarySupported(group, addrconfig.AncillaryID(option.Canonical)) {
		return false
	}
	groups := option.Scope.ImplGroups
	return len(groups) == 0 || slices.Contains(groups, group)
}
