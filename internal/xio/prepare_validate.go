package xio

import (
	"fmt"
	"slices"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/optionmeta"
	"github.com/oittaa/socat/internal/parse"
)

func rejectUnknownOptions(spec parse.Spec, desc AddressDesc, registered bool) error {
	return rejectAddressOptions(spec, desc, registered, false)
}

func rejectOptionScope(spec parse.Spec, desc AddressDesc, registered bool) error {
	return rejectAddressOptions(spec, desc, registered, true)
}

func rejectAddressOptions(spec parse.Spec, desc AddressDesc, registered, scope bool) error {
	reg := registrationSnapshot(desc)
	for _, option := range spec.Options {
		optionSpec, ok := lookupAddressOption(option)
		if !ok {
			return fmt.Errorf("%s: unknown option %q", spec.Type, option.Name)
		}
		if !registered {
			continue
		}
		if !scope {
			if !optionImplementedForGroup(desc.Group, optionSpec) {
				return fmt.Errorf("%s: option %q not supported with this address type", spec.Type, option.Name)
			}
			continue
		}
		s := optionSpec.Scope
		if !OptionSupportedOnAddress(reg, s.AddressGroups, s.AddressTypes, s.Caps) {
			return fmt.Errorf("%s: option %q not supported with this address type", spec.Type, option.Name)
		}
		if s.RestrictTypes && !addressTypeAllowed(desc.Name, s.AddressTypes) {
			return fmt.Errorf("%s: option %q not supported with this address type", spec.Type, option.Name)
		}
	}
	return nil
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
			return optionmeta.Option{Scope: optionmeta.AddressScope{Caps: []string{CapTermios}}}, true
		}
	}
	return optionmeta.Option{}, false
}

func optionImplementedForGroup(group string, option optionmeta.Option) bool {
	if !IPAncillarySupported(group, option.Canonical) {
		return false
	}
	groups := option.Scope.ImplGroups
	return len(groups) == 0 || slices.Contains(groups, group)
}
