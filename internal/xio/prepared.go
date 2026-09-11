package xio

import (
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
)

// PreparedAddress pairs immutable decoded settings with the opener selected by
// the address registry. The parser representation is retained privately only
// while address-family migration is in progress; execution code must consume
// Config rather than parse options.
type PreparedAddress struct {
	Config addrconfig.Address

	opener Opener
	legacy parse.Spec
}

// PreparedDual is a decoded dual address.
type PreparedDual struct {
	Left  PreparedAddress
	Right PreparedAddress
	Raw   string
}

// PreparedChannel is the typed boundary between syntax and resource opening.
type PreparedChannel struct {
	Single *PreparedAddress
	Dual   *PreparedDual
	Raw    string
}

// IsDual reports whether the prepared channel contains two addresses.
func (c PreparedChannel) IsDual() bool { return c.Dual != nil }

// PrepareChannel resolves registration identities and decodes each address
// without acquiring resources. Both CLI and constructed channels enter here.
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

// PrepareSpec resolves one registered address before its static configuration
// is decoded. It does not access files, DNS, or other runtime resources.
func PrepareSpec(spec parse.Spec) (PreparedAddress, error) {
	spec = clonePreparedSpec(spec)
	typ := strings.ToUpper(strings.TrimSpace(spec.Type))
	desc, ok := registeredAddresses.resolve(typ)
	if !ok || desc.Opener == nil {
		return PreparedAddress{}, fmt.Errorf("unknown device/address %q", typ)
	}
	spec.Type = desc.Name
	config, err := addrconfig.Decode(spec, addrconfig.Facts{
		Type:  desc.Name,
		Group: desc.Group,
		Caps:  desc.OptionCaps,
	})
	if err != nil {
		return PreparedAddress{}, err
	}
	return PreparedAddress{Config: config, opener: desc.Opener, legacy: spec}, nil
}

func clonePreparedSpec(spec parse.Spec) parse.Spec {
	spec.Params = append([]string(nil), spec.Params...)
	spec.Options = append([]parse.Option(nil), spec.Options...)
	return spec
}
