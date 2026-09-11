package xio

import (
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/addrconfig"
)

// maxIPOptions is the accumulated IP_OPTIONS byte cap (getsockopt buffer
// and append).
const maxIPOptions = 256

// ApplyIPSendOpts sets send-side IP options on an INET fd. Production INET
// sockets apply send and recv IP/ancillary options together after socket()
// via ApplyPastSocketPhase (DialControl / ListenControl, including raw IP).
// This send-only helper remains for leftover callers such as
// ApplyIPSendOptsToPacketConn.
func ApplyIPSendOpts(fd int, s addrconfig.Address, network string) error {
	return applyClassicIPSendOpts(fd, s, ipFamilyFromNetwork(network))
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
func applyClassicIPSendOpts(fd int, s addrconfig.Address, family ipFamily) error {
	config := s
	got, err := resolveApplyIPFamily(fd, family)
	if err != nil {
		return err
	}
	resolved := got
	for _, action := range config.Network.Actions {
		if action.Kind != addrconfig.SocketActionAncillary {
			continue
		}
		name, kind, ok := ancillaryOptionIdentity(action.Ancillary)
		if !ok || kind&IPAncillarySend == 0 {
			continue
		}
		e, inMatrix := lookupIPAncillary(name)
		if !inMatrix {
			continue
		}
		if err := applyPreparedIPSend(fd, e, action, resolved); err != nil {
			return err
		}
	}
	return nil
}

func applyPreparedAncillary(fd int, action addrconfig.SocketAction, family *ipFamily, familyResolved *bool) error {
	name, kind, ok := ancillaryOptionIdentity(action.Ancillary)
	if !ok {
		return nil
	}
	e, inMatrix := lookupIPAncillary(name)
	if !inMatrix {
		return nil
	}
	if familyResolved != nil && !*familyResolved {
		got, err := socketIPFamily(fd)
		if err != nil {
			return err
		}
		*family = got
		*familyResolved = true
	}
	resolved := ipFamilyUnknown
	if family != nil {
		resolved = *family
	}
	switch {
	case kind&IPAncillarySend != 0:
		return applyPreparedIPSend(fd, e, action, resolved)
	case kind&IPAncillaryRecv != 0:
		return applyPreparedIPRecv(fd, e, action.Number, resolved)
	default:
		return nil
	}
}

func applyPreparedIPSend(fd int, e IPAncillaryEntry, action addrconfig.SocketAction, family ipFamily) error {
	if err := rejectIPAncillaryApply(e.Canonical, family); err != nil {
		return err
	}
	switch e.Canonical {
	case "ip-options":
		if len(action.Value.Bytes) == 0 {
			return nil
		}
		if err := applyIPOptionsBytes(fd, action.Value.Bytes); err != nil {
			return fmt.Errorf("ip-options: %w", err)
		}
		return nil
	case "ip-hdrincl":
		if err := applyIPHdrincl(fd, action.Number); err != nil {
			return fmt.Errorf("%s: %w", e.Canonical, err)
		}
		return nil
	case "ip-ttl":
		if err := setSockoptInt(fd, ipLevelIP, ipOptTTL, action.Number); err != nil {
			return fmt.Errorf("%s: %w", e.Canonical, err)
		}
		return nil
	case "ip-tos":
		if err := setSockoptInt(fd, ipLevelIP, ipOptTOS, action.Number); err != nil {
			return fmt.Errorf("%s: %w", e.Canonical, err)
		}
		return nil
	case "ipv6-unicast-hops":
		if err := setSockoptInt(fd, ipLevelIPv6, ipOptUnicastHops, action.Number); err != nil {
			return fmt.Errorf("%s: %w", e.Canonical, err)
		}
		return nil
	case "ipv6-tclass":
		if err := applyIPv6Tclass(fd, action.Number); err != nil {
			return fmt.Errorf("%s: %w", e.Canonical, err)
		}
		return nil
	default:
		return nil
	}
}
