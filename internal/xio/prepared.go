package xio

import (
	"context"
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

type PreparedAddress struct {
	Config addrconfig.Address
	opener opener
}

type preparedDual struct {
	Left  PreparedAddress
	Right PreparedAddress
	Raw   string
}

type preparedChannel struct {
	Single *PreparedAddress
	Dual   *preparedDual
	Raw    string
}

func (c preparedChannel) IsDual() bool { return c.Dual != nil }

func PrepareChannel(ch parse.Channel) (preparedChannel, error) {
	if ch.Single != nil {
		a, err := PrepareSpec(*ch.Single)
		if err != nil {
			return preparedChannel{}, err
		}
		return preparedChannel{Single: &a, Raw: ch.Raw}, nil
	}
	if ch.Dual != nil {
		left, err := PrepareSpec(ch.Dual.Left)
		if err != nil {
			return preparedChannel{}, fmt.Errorf("dual left: %w", err)
		}
		right, err := PrepareSpec(ch.Dual.Right)
		if err != nil {
			return preparedChannel{}, fmt.Errorf("dual right: %w", err)
		}
		return preparedChannel{Dual: &preparedDual{Left: left, Right: right, Raw: ch.Dual.Raw}, Raw: ch.Raw}, nil
	}
	return preparedChannel{}, fmt.Errorf("xio: empty channel")
}

func PrepareSpec(spec parse.Spec) (PreparedAddress, error) {
	typ := strings.ToUpper(strings.TrimSpace(spec.Type))
	desc, registered := registeredAddresses.resolve(typ)
	options, err := resolveAddressOptions(spec, desc, registered)
	if err != nil {
		return PreparedAddress{}, err
	}
	facts := addrconfig.Facts{Type: spec.Type}
	if registered {
		facts = addrconfig.Facts{
			Type:   desc.Name,
			Group:  desc.Group,
			Caps:   desc.OptionCaps,
			Kind:   desc.Kind,
			Role:   desc.Role,
			Family: desc.Family,
		}
	}
	// Unknown option, then a bad option value, then an option that does not
	// apply, then the parameter count. Option values are decoded once.
	// Positional parameters are applied after the count check.
	decoded, err := addrconfig.DecodeOptions(spec, facts, options.definitions)
	if err != nil {
		return PreparedAddress{}, err
	}
	if options.scopeError != nil {
		return PreparedAddress{}, options.scopeError
	}
	if registered {
		if err := validateAddressParams(spec, desc); err != nil {
			return PreparedAddress{}, err
		}
	}
	config, err := decoded.Finish(spec)
	if err != nil {
		return PreparedAddress{}, err
	}
	if err := rejectPreparedStaticChecks(config); err != nil {
		return PreparedAddress{}, err
	}
	if err := resolvePreparedOwners(&config); err != nil {
		return PreparedAddress{}, err
	}
	if options.platformError != nil {
		return PreparedAddress{}, options.platformError
	}
	if err := rejectUnsupportedRemainingIPv4(config); err != nil {
		return PreparedAddress{}, err
	}
	if !registered || desc.Opener == nil {
		return PreparedAddress{}, fmt.Errorf("unknown device/address %q", typ)
	}
	return PreparedAddress{Config: config, opener: desc.Opener}, nil
}

// OpenWithType dispatches to another registered opener at resource time.
// GOPEN uses this after Stat shows a UNIX socket. Address is passed by
// value, so the prepared GOPEN config is not rewritten. This is not a
// second PrepareSpec; static checks already ran for the original address.
func OpenWithType(ctx context.Context, name string, config addrconfig.Address, mode Mode, g *Global) (*Opened, error) {
	desc, ok := registeredAddresses.resolve(name)
	if !ok || desc.Opener == nil {
		return nil, fmt.Errorf("unknown device/address %q", name)
	}
	config.Type = desc.Name
	config.Facts = addrconfig.Facts{
		Type:   desc.Name,
		Group:  desc.Group,
		Caps:   append([]string(nil), desc.OptionCaps...),
		Kind:   desc.Kind,
		Role:   desc.Role,
		Family: desc.Family,
	}
	return desc.Opener(ctx, config, mode, g)
}
