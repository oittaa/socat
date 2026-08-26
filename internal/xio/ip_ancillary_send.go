package xio

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// ApplyIPSendOpts sets classic send-side IP options on an INET fd.
// DialControl / ListenControl apply these once at PH_PASTSOCKET via
// ApplyNetworkSocketOptions; raw-IP sockets that have no Control callback
// call this after ListenIP/DialIP.
func ApplyIPSendOpts(fd int, s parse.Spec, network string) error {
	return applyClassicIPSendOpts(fd, s, ipFamilyFromNetwork(network))
}

// applyIPTTLTOS is the PH_PASTSOCKET owner for send-side IP options on Go
// net sockets. Called from ApplyNetworkSocketOptions (DialControl /
// ListenControl) after socket() and before bind/connect. Skips UNIX/VSOCK
// and other non-INET networks. Classic: xio-ip.c / xio-ip6.c OFUNC_SOCKOPT
// at PH_PASTSOCKET (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba;
// official master af5388c898c7bb60997935aee93c223deba60c4a is the same tree).
func applyIPTTLTOS(fd int, s parse.Spec, network string) error {
	if !ipSendAppliesToNetwork(network) {
		return nil
	}
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

func specOptionName(o parse.Option) string {
	if o.Name != "" {
		return o.Name
	}
	return o.OriginalSpelling()
}

// applyClassicIPSendOpts applies send-side IP options with classic levels from
// xio-ip.c / xio-ip6.c (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba;
// official master af5388c898c7bb60997935aee93c223deba60c4a is the same tree):
// ip-ttl/ip-tos/ip-options use OFUNC_SOCKOPT SOL_IP (IPPROTO_IP) IP_TTL/IP_TOS/
// IP_OPTIONS even on IPv6 sockets. ipv6-unicast-hops/ipv6-tclass use SOL_IPV6
// and are rejected on IPv4 rather than skipped.
//
// Classic applyopts walks every matching option in command-line order, so
// ttl=1,ip-ttl=64 is two setsockopt calls (not OptionNamed last-wins). An
// earlier kernel-invalid value still fails even if a later value is valid.
func applyClassicIPSendOpts(fd int, s parse.Spec, family ipFamily) error {
	if family == ipFamilyUnknown {
		got, err := socketIPFamily(fd)
		if err != nil {
			return err
		}
		family = got
	}
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
