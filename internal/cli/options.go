package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/optionmeta"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func validateChannelOptions(ch parse.Channel) error {
	if ch.Single != nil {
		return validateSpecOptions(*ch.Single)
	}
	if ch.Dual != nil {
		if err := validateSpecOptions(ch.Dual.Left); err != nil {
			return fmt.Errorf("dual left: %w", err)
		}
		if err := validateSpecOptions(ch.Dual.Right); err != nil {
			return fmt.Errorf("dual right: %w", err)
		}
	}
	return nil
}

func validateSpecOptions(spec parse.Spec) error {
	// Same isolation names OpenSpec rejects; recognize them here so CLI
	// validation does not report "unknown option".
	if err := xio.RejectUnsupportedIsolation(spec); err != nil {
		return err
	}
	// Validate names, implementation families, and values first.
	registration, registered := xio.AddressRegistrationForType(spec.Type)
	for _, option := range spec.Options {
		optionSpec, ok := lookupAddressOption(option)
		if !ok {
			return fmt.Errorf("%s: unknown option %q", spec.Type, option.Name)
		}
		if registered && !optionImplementedForGroup(registration.Group, optionSpec) {
			return fmt.Errorf("%s: option %q not supported with this address type", spec.Type, option.Name)
		}
		if err := validateAddressOptionValue(option); err != nil {
			return fmt.Errorf("%s: %w", spec.Type, err)
		}
	}
	// Preserve the specific runtime rejection reasons before checking scope.
	if err := xio.RejectUnsupportedIPAncillary(spec); err != nil {
		return err
	}
	if err := xio.RejectUnsupportedTermios(spec); err != nil {
		return err
	}
	if err := xio.RejectUnsupportedRecvErr(spec); err != nil {
		return err
	}
	if err := xio.ValidateDescriptorModeOptions(spec); err != nil {
		return err
	}
	if err := xio.RejectUnsupportedListenBacklog(spec); err != nil {
		return err
	}
	for _, option := range spec.Options {
		optionSpec, ok := lookupAddressOption(option)
		if !ok {
			return fmt.Errorf("%s: unknown option %q", spec.Type, option.Name)
		}
		// Prefer the public spelling so ipv6-join-group stays IPv6-only
		// even if Name was folded onto ip-add-membership.
		scope := optionSpec.Scope
		if registered && !xio.OptionSupportedOnAddress(registration, scope.AddressGroups, scope.AddressTypes, scope.Caps) {
			return fmt.Errorf("%s: option %q not supported with this address type", spec.Type, option.Name)
		}
		// INTERFACE options also match TUN. restrictAddressTypes
		// (retrieve-vlan) is a hard allow-list so TUN is rejected at CLI.
		if registered && scope.RestrictTypes && !addressTypeAllowed(registration.Name, scope.AddressTypes) {
			return fmt.Errorf("%s: option %q not supported with this address type", spec.Type, option.Name)
		}
	}
	config, err := decodeSpecConfig(spec)
	if err != nil {
		return err
	}
	if err := xio.RejectUnsupportedRemainingIPv4(config); err != nil {
		return err
	}
	return nil
}

func decodeSpecConfig(spec parse.Spec) (addrconfig.Address, error) {
	facts := addrconfig.Facts{Type: spec.Type}
	if registration, ok := xio.AddressRegistrationForType(spec.Type); ok {
		facts.Type = registration.Name
		facts.Group = registration.Group
		facts.Caps = registration.OptionCaps
	}
	return addrconfig.Decode(spec, facts)
}

// Prefer the original spelling; public aliases need not fold during parsing.
func lookupAddressOption(option parse.Option) (optionmeta.Option, bool) {
	for _, name := range []string{option.OriginalSpelling(), option.Name} {
		if def, ok := optionmeta.Lookup(name); ok {
			return def, true
		}
		if xio.IsTermiosOption(name) {
			return optionmeta.Option{Scope: optionmeta.AddressScope{Caps: []string{xio.CapTermios}}}, true
		}
	}
	return optionmeta.Option{}, false
}

func addressTypeAllowed(addressType string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if strings.EqualFold(addressType, candidate) {
			return true
		}
	}
	return false
}

// optionImplementedForGroup narrows socket-wide options to the address
// families that currently apply them. Without this guard the CLI would
// accept options an opener then silently ignores.
func optionImplementedForGroup(group string, option optionmeta.Option) bool {
	if !xio.IPAncillarySupported(group, option.Canonical) {
		return false
	}
	groups := option.Scope.ImplGroups
	return len(groups) == 0 || slices.Contains(groups, group)
}
