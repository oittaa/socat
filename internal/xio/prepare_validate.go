package xio

import (
	"fmt"
	"slices"
	"strings"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/optionmeta"
	"github.com/oittaa/socat/internal/parse"
)

type resolvedAddressOptions struct {
	definitions []optionmeta.Option
	scopeError  error
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
		if !registered {
			continue
		}
		if !optionImplementedForGroup(desc.Group, optionSpec) {
			return resolvedAddressOptions{}, fmt.Errorf("%s: option %q not supported with this address type", spec.Type, option.Name)
		}
		s := optionSpec.Scope
		if resolved.scopeError == nil &&
			(!OptionSupportedOnAddress(reg, s.AddressGroups, s.AddressTypes, s.Caps) ||
				s.RestrictTypes && !addressTypeAllowed(desc.Name, s.AddressTypes)) {
			resolved.scopeError = fmt.Errorf("%s: option %q not supported with this address type", spec.Type, option.Name)
		}
	}
	return resolved, nil
}

func rejectPreparedStaticChecks(config addrconfig.Address) error {
	if err := RejectUnsupportedIPAncillary(config); err != nil {
		return err
	}
	if err := RejectUnsupportedTermios(config); err != nil {
		return err
	}
	if err := RejectUnsupportedRecvErr(config); err != nil {
		return err
	}
	if err := ValidateDescriptorModeOptions(config); err != nil {
		return err
	}
	if err := RejectUnsupportedListenBacklog(config); err != nil {
		return err
	}
	return RejectUnsupportedUnixTightSocklen(config)
}

func lookupAddressOption(option parse.Option) (optionmeta.Option, bool) {
	for _, name := range []string{option.OriginalSpelling(), option.Name} {
		if def, ok := optionmeta.Lookup(name); ok {
			return def, true
		}
		if IsTermiosOption(name) {
			canonical := strings.ToLower(strings.TrimSpace(option.Name))
			if canonical == "" {
				canonical = strings.ToLower(strings.TrimSpace(name))
			}
			return optionmeta.Option{
				Canonical: canonical,
				Scope:     optionmeta.AddressScope{Caps: []string{CapTermios}},
			}, true
		}
	}
	return optionmeta.Option{}, false
}

func optionImplementedForGroup(group string, option optionmeta.Option) bool {
	if !IPAncillarySupported(group, addrconfig.AncillaryID(option.Canonical)) {
		return false
	}
	groups := option.Scope.ImplGroups
	return len(groups) == 0 || slices.Contains(groups, group)
}
