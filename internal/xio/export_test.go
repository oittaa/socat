package xio

import (
	"context"
	"sort"

	"github.com/oittaa/socat/internal/parse"
)

// Test-only wrappers around the prepared open and run path. Production
// enters through PrepareChannel and RunPrepared.

func OpenChannel(ctx context.Context, ch parse.Channel, mode Mode, g *Global) (*Opened, error) {
	prepared, err := PrepareChannel(ch)
	if err != nil {
		return nil, err
	}
	return OpenPreparedChannel(ctx, prepared, mode, g)
}

func OpenSpec(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	prepared, err := PrepareSpec(s)
	if err != nil {
		return nil, err
	}
	return OpenPreparedSpec(ctx, prepared, mode, g)
}

func Run(ctx context.Context, left, right parse.Channel, g *Global) error {
	preparedLeft, err := PrepareChannel(left)
	if err != nil {
		return err
	}
	preparedRight, err := PrepareChannel(right)
	if err != nil {
		return err
	}
	return RunPrepared(ctx, preparedLeft, preparedRight, g)
}

func RunOpened(ctx context.Context, lo *Opened, right parse.Channel, g *Global) error {
	prepared, err := PrepareChannel(right)
	if err != nil {
		if lo != nil {
			_ = lo.Close()
		}
		return err
	}
	return RunOpenedPrepared(ctx, lo, prepared, g)
}

func AddressAliasMap() map[string]string {
	return registeredAddresses.aliasMap()
}

func (r *addressRegistry) aliasMap() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]string, len(r.aliases))
	for alias, dest := range r.aliases {
		out[alias] = dest
	}
	return out
}

func AddressRegistrations() []AddressRegistration {
	return registeredAddresses.registrations()
}

func (r *addressRegistry) registrations() []AddressRegistration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := map[string]bool{}
	var out []AddressRegistration
	for _, group := range r.orderedGroupsLocked() {
		descs := r.addrsByGroup[group]
		for _, d := range descs {
			name := d.Name
			seen[name] = true
			out = append(out, registrationSnapshot(d))
		}
	}
	var hidden []string
	for name := range r.openers {
		if !seen[name] {
			hidden = append(hidden, name)
		}
	}
	sort.Strings(hidden)
	for _, name := range hidden {
		out = append(out, registrationSnapshot(r.descsByName[name]))
	}
	return out
}
