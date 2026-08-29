package xio

import (
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// maxIPOptions is the accumulated IP_OPTIONS byte cap (getsockopt buffer
// and append).
const maxIPOptions = 256

// ApplyIPSendOpts sets send-side IP options on an INET fd. Production INET
// sockets apply send and recv IP/ancillary options together after socket()
// via ApplyPastSocketPhase (DialControl / ListenControl, including raw IP).
// This send-only helper remains for leftover callers such as
// ApplyIPSendOptsToPacketConn.
func ApplyIPSendOpts(fd int, s parse.Spec, network string) error {
	return applyClassicIPSendOpts(fd, s, ipFamilyFromNetwork(network))
}

// applyOrderedPastSocketPhaseOptions applies every post-socket() action
// option in one pass over Spec.Options, after socket() and before
// bind/connect: fixed SOL_SOCKET options (broadcast, sndbuf/rcvbuf,
// bindtodevice, linger, timeos), named SOL_SOCKET/TCP/SCTP options,
// FIOSETOWN/SIOCSPGRP owner ioctls, generic setsockopt-socket, and
// IP/ancillary/membership options. Occurrences keep original command-line
// order, including when a generic option targets the same kernel setting
// as a named option.
func applyOrderedPastSocketPhaseOptions(fd int, s parse.Spec, network string) error {
	applyIP := ipSendAppliesToNetwork(network)
	family := ipFamilyFromNetwork(network)
	familyResolved := family != ipFamilyUnknown
	for _, option := range s.Options {
		if matched, err := applyFixedPastSocketOption(fd, option); matched {
			if err != nil {
				return err
			}
			continue
		}
		if matched, err := applyNamedPastSocketSockopt(fd, option); matched {
			if err != nil {
				return err
			}
			continue
		}
		if matched, err := applyOwnerIoctlOption(fd, option); matched {
			if err != nil {
				return err
			}
			continue
		}
		if kind, ok := genericSetsockoptKind(option.Name, SockoptPhasePastSocket); ok {
			if err := applyGenericSetsockoptOption(fd, option, kind); err != nil {
				return err
			}
			continue
		}
		if !applyIP {
			continue
		}
		if matched, err := applyMembershipOption(fd, option); matched {
			if err != nil {
				return err
			}
			continue
		}
		if matched, err := applySourceMembershipOption(fd, option); matched {
			if err != nil {
				return err
			}
			continue
		}
		if matched, err := applyMulticastNamedOption(fd, option); matched {
			if err != nil {
				return err
			}
			continue
		}
		if matched, err := applyFreebindOption(fd, option); matched {
			if err != nil {
				return err
			}
			continue
		}
		if matched, err := applyMTUDiscoveryOption(fd, option); matched {
			if err != nil {
				return err
			}
			continue
		}
		if matched, err := applyRecvErrOption(fd, option); matched {
			if err != nil {
				return err
			}
			continue
		}
		if matched, err := applyGetOnlyIPOption(fd, option); matched {
			if err != nil {
				return err
			}
			continue
		}
		if matched, err := applyRouterAlertOption(fd, option); matched {
			if err != nil {
				return err
			}
			continue
		}
		e, ok := lookupIPAncillary(specOptionName(option))
		if !ok {
			continue
		}
		if !familyResolved {
			got, err := socketIPFamily(fd)
			if err != nil {
				return err
			}
			family = got
			familyResolved = true
		}
		switch {
		case e.Kind&IPAncillarySend != 0:
			if err := applyOneIPSendOpt(fd, e, option, family); err != nil {
				return err
			}
		case e.Kind&IPAncillaryRecv != 0:
			if err := applyOneIPRecvOpt(fd, e, option, family); err != nil {
				return err
			}
		}
	}
	return nil
}

func ipSendAppliesToNetwork(network string) bool {
	n := strings.ToLower(network)
	if i := strings.IndexByte(n, ':'); i >= 0 {
		n = n[:i]
	}
	switch {
	case strings.HasPrefix(n, "tcp"), strings.HasPrefix(n, "udp"), strings.HasPrefix(n, "sctp"):
		return true
	case n == "ip", n == "ip4", n == "ip6":
		return true
	default:
		return false
	}
}

func specOptionName(o parse.Option) string {
	if o.Name != "" {
		return o.Name
	}
	return o.OriginalSpelling()
}

func resolveApplyIPFamily(fd int, family ipFamily) (ipFamily, error) {
	if family != ipFamilyUnknown {
		return family, nil
	}
	return socketIPFamily(fd)
}

// applyClassicIPSendOpts applies send-side IP options in command-line
// order: ip-ttl/ip-tos use IPPROTO_IP IP_TTL/IP_TOS even on IPv6 sockets;
// ip-options appends to IP_OPTIONS; ipv6-unicast-hops/ipv6-tclass use
// IPPROTO_IPV6 and are rejected on IPv4 rather than skipped; ip-hdrincl
// uses IP_HDRINCL on raw IPv4 only (bare flag → 1). ttl=1,ip-ttl=64 is two
// setsockopt calls, not last-wins. An earlier kernel-invalid value still
// fails even if a later value is valid.
func applyClassicIPSendOpts(fd int, s parse.Spec, family ipFamily) error {
	got, err := resolveApplyIPFamily(fd, family)
	if err != nil {
		return err
	}
	family = got
	for _, option := range s.Options {
		e, ok := lookupIPAncillary(specOptionName(option))
		if !ok || e.Kind&IPAncillarySend == 0 {
			continue
		}
		if err := applyOneIPSendOpt(fd, e, option, family); err != nil {
			return err
		}
	}
	return nil
}

func applyOneIPSendOpt(fd int, e IPAncillaryEntry, option parse.Option, family ipFamily) error {
	if err := rejectIPAncillaryApply(e.Canonical, family); err != nil {
		return err
	}
	if e.Canonical == "ip-options" {
		if !option.Has {
			return nil
		}
		v := strings.TrimSpace(option.Value)
		if v == "" {
			return nil
		}
		// Each occurrence appends; stop on error.
		if err := applyIPOptions(fd, v); err != nil {
			return fmt.Errorf("ip-options: %w", err)
		}
		return nil
	}
	if e.Canonical == "ip-hdrincl" {
		// Bare flag → 1.
		n := 1
		if option.Has {
			v := strings.TrimSpace(option.Value)
			if v != "" {
				parsed, err := ParseIntAny(v)
				if err != nil {
					return fmt.Errorf("%s: %w", e.Canonical, err)
				}
				n = parsed
			}
		}
		if err := applyIPHdrincl(fd, n); err != nil {
			return fmt.Errorf("%s: %w", e.Canonical, err)
		}
		return nil
	}
	if !option.Has || strings.TrimSpace(option.Value) == "" {
		return nil
	}
	n, err := ParseIntAny(option.Value)
	if err != nil {
		return fmt.Errorf("%s: %w", e.Canonical, err)
	}
	switch e.Canonical {
	case "ip-ttl":
		err = setSockoptInt(fd, ipLevelIP, ipOptTTL, n)
	case "ip-tos":
		err = setSockoptInt(fd, ipLevelIP, ipOptTOS, n)
	case "ipv6-unicast-hops":
		err = setSockoptInt(fd, ipLevelIPv6, ipOptUnicastHops, n)
	case "ipv6-tclass":
		err = applyIPv6Tclass(fd, n)
	default:
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", e.Canonical, err)
	}
	return nil
}

// ParseHexOpt parses ip-options= dalan data. Default type is 'i', so x0102
// is two hex bytes while an unprefixed 1 is one native C int; treating the
// leading x as optional silently changes values.
func ParseHexOpt(v string) ([]byte, error) {
	data, _, err := ParseDalan(strings.TrimSpace(v), 'i')
	if err != nil {
		return nil, err
	}
	if len(data) > maxIPOptions {
		return nil, fmt.Errorf("value exceeds %d bytes", maxIPOptions)
	}
	return data, nil
}
