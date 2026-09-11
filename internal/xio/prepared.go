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
	opener Opener
}

type PreparedDual struct {
	Left  PreparedAddress
	Right PreparedAddress
	Raw   string
}

type PreparedChannel struct {
	Single *PreparedAddress
	Dual   *PreparedDual
	Raw    string
}

type preparedConfigKey struct{}

func withPreparedConfig(ctx context.Context, config addrconfig.Address) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, preparedConfigKey{}, config)
}

func PreparedConfig(ctx context.Context) (addrconfig.Address, bool) {
	if ctx == nil {
		return addrconfig.Address{}, false
	}
	config, ok := ctx.Value(preparedConfigKey{}).(addrconfig.Address)
	return config, ok
}

func (c PreparedChannel) IsDual() bool { return c.Dual != nil }

func PrepareChannel(ch parse.Channel) (PreparedChannel, error) {
	if ch.Single != nil {
		a, err := PrepareSpec(*ch.Single)
		if err != nil {
			return PreparedChannel{}, err
		}
		return PreparedChannel{Single: &a, Raw: ch.Raw}, nil
	}
	if ch.Dual != nil {
		left, err := PrepareSpec(ch.Dual.Left)
		if err != nil {
			return PreparedChannel{}, fmt.Errorf("dual left: %w", err)
		}
		right, err := PrepareSpec(ch.Dual.Right)
		if err != nil {
			return PreparedChannel{}, fmt.Errorf("dual right: %w", err)
		}
		return PreparedChannel{Dual: &PreparedDual{Left: left, Right: right, Raw: ch.Dual.Raw}, Raw: ch.Raw}, nil
	}
	return PreparedChannel{}, fmt.Errorf("xio: empty channel")
}

func PrepareSpec(spec parse.Spec) (PreparedAddress, error) {
	typ := strings.ToUpper(strings.TrimSpace(spec.Type))
	desc, registered := registeredAddresses.resolve(typ)
	if err := rejectUnknownOptions(spec, desc, registered); err != nil {
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
	config, err := addrconfig.Decode(spec, facts)
	if err != nil {
		return PreparedAddress{}, err
	}
	if err := rejectPreparedStaticChecks(config); err != nil {
		return PreparedAddress{}, err
	}
	if err := rejectOptionScope(spec, desc, registered); err != nil {
		return PreparedAddress{}, err
	}
	if err := RejectUnsupportedRemainingIPv4(config); err != nil {
		return PreparedAddress{}, err
	}
	if !registered || desc.Opener == nil {
		return PreparedAddress{}, fmt.Errorf("unknown device/address %q", typ)
	}
	return PreparedAddress{Config: config, opener: desc.Opener}, nil
}

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
