package xio

import (
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// Classic parseopts_table uses a 256-byte buffer for TYPE_BIN, and
// OFUNC_SOCKOPT_APPEND uses the same limit for the accumulated IP_OPTIONS.
const maxIPOptions = 256

// ApplyIPSendOpts sets classic send-side IP options on an INET fd.
// Production INET sockets apply send and recv IP/ancillary options together
// at PH_PASTSOCKET via ApplyPastSocketPhase (DialControl / ListenControl,
// including raw IP). This send-only helper remains for leftover callers
// such as ApplyIPSendOptsToPacketConn.
func ApplyIPSendOpts(fd int, s parse.Spec, network string) error {
	return applyClassicIPSendOpts(fd, s, ipFamilyFromNetwork(network))
}

// applyOrderedPastSocketPhaseOptions applies generic and IP/ancillary
// PH_PASTSOCKET options in one pass over Spec.Options, after socket() and
// before bind/connect. Send (IP_TTL, IP_TOS, IP_OPTIONS, …), recv
// (IP_RECVTTL, IP_PKTINFO, …), and setsockopt-socket are applied in original
// command-line order, including when a generic option targets the same kernel
// setting as a named option.
// Classic: xio-ip.c / xio-ip6.c OFUNC_SOCKOPT / OFUNC_SOCKOPT_APPEND at
// PH_PASTSOCKET; applyopts in xioopts.c (tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same tree).
func applyOrderedPastSocketPhaseOptions(fd int, s parse.Spec, network string) error {
	applyIP := ipSendAppliesToNetwork(network)
	family := ipFamilyFromNetwork(network)
	familyResolved := family != ipFamilyUnknown
	for _, option := range s.Options {
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

// applyClassicIPSendOpts applies send-side IP options with classic levels from
// xio-ip.c / xio-ip6.c (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba;
// official master af5388c898c7bb60997935aee93c223deba60c4a is the same tree):
// ip-ttl/ip-tos use OFUNC_SOCKOPT SOL_IP (IPPROTO_IP) IP_TTL/IP_TOS even on
// IPv6 sockets. ip-options uses OFUNC_SOCKOPT_APPEND SOL_IP IP_OPTIONS.
// ipv6-unicast-hops/ipv6-tclass use SOL_IPV6 and are rejected on IPv4 rather
// than skipped.
//
// Classic applyopts walks every matching option in command-line order, so
// ttl=1,ip-ttl=64 is two setsockopt calls (not OptionNamed last-wins). An
// earlier kernel-invalid value still fails even if a later value is valid.
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
		// Each occurrence appends (classic OFUNC_SOCKOPT_APPEND); stop on error.
		if err := applyIPOptions(fd, v); err != nil {
			return fmt.Errorf("ip-options: %w", err)
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

// ParseHexOpt parses classic ip-options= TYPE_BIN data. Classic dalan uses
// default type 'i', so x0102 is two hex bytes while an unprefixed 1 is one
// native C int; treating the leading x as optional silently changes values.
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
