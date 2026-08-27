package xio

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// ApplyIPSendOpts sets classic send-side IP options on an INET fd.
// Production INET sockets apply send and recv IP/ancillary options together
// at PH_PASTSOCKET via ApplyPastSocketPhase (DialControl / ListenControl,
// including raw IP). This send-only helper remains for leftover callers
// such as ApplyIPSendOptsToPacketConn.
func ApplyIPSendOpts(fd int, s parse.Spec, network string) error {
	return applyClassicIPSendOpts(fd, s, ipFamilyFromNetwork(network))
}

// ApplyPastSocketPhase applies classic PH_PASTSOCKET IP/ancillary options
// in one pass over Spec.Options, after socket() and before bind/connect.
// Send (IP_TTL, IP_TOS, IP_OPTIONS, …) and recv (IP_RECVTTL, IP_PKTINFO, …)
// are classified and applied in original command-line order so
// ip-recvttl=1,ip-ttl=64 is not split across bind.
// Classic: xio-ip.c / xio-ip6.c OFUNC_SOCKOPT / OFUNC_SOCKOPT_APPEND at
// PH_PASTSOCKET; applyopts in xioopts.c (tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same tree).
func ApplyPastSocketPhase(fd int, s parse.Spec, network string) error {
	if !ipSendAppliesToNetwork(network) {
		return nil
	}
	return applyClassicIPPastSocketOpts(fd, s, ipFamilyFromNetwork(network))
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

// applyClassicIPPastSocketOpts applies send and recv IP/ancillary options
// in one command-line walk (classic applyopts PH_PASTSOCKET).
func applyClassicIPPastSocketOpts(fd int, s parse.Spec, family ipFamily) error {
	got, err := resolveApplyIPFamily(fd, family)
	if err != nil {
		return err
	}
	family = got
	for _, option := range s.Options {
		e, ok := lookupIPAncillary(specOptionName(option))
		if !ok {
			continue
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

// ParseHexOpt decodes a classic ip-options= hex dump (optional x / 0x prefix).
func ParseHexOpt(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "x") || strings.HasPrefix(v, "X") {
		v = v[1:]
	}
	if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
		v = v[2:]
	}
	return hex.DecodeString(v)
}
