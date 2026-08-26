package xio

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// applyClassicIPSendOpts applies send-side IP options with classic levels from
// xio-ip.c / xio-ip6.c (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba;
// official master af5388c898c7bb60997935aee93c223deba60c4a is the same tree):
// ip-ttl/ip-tos/ip-options use OFUNC_SOCKOPT SOL_IP (IPPROTO_IP) IP_TTL/IP_TOS/
// IP_OPTIONS even on IPv6 sockets. ipv6-unicast-hops/ipv6-tclass use SOL_IPV6
// and are rejected on IPv4 rather than skipped.
func applyClassicIPSendOpts(fd int, s parse.Spec, family ipFamily) error {
	if family == ipFamilyUnknown {
		got, err := socketIPFamily(fd)
		if err != nil {
			return err
		}
		family = got
	}
	if n, ok, err := ipSendInt(s, "ip-ttl"); err != nil {
		return fmt.Errorf("ip-ttl: %w", err)
	} else if ok {
		if err := setSockoptInt(fd, ipLevelIP, ipOptTTL, n); err != nil {
			return fmt.Errorf("ip-ttl: %w", err)
		}
	}
	if n, ok, err := ipSendInt(s, "ip-tos"); err != nil {
		return fmt.Errorf("ip-tos: %w", err)
	} else if ok {
		if err := setSockoptInt(fd, ipLevelIP, ipOptTOS, n); err != nil {
			return fmt.Errorf("ip-tos: %w", err)
		}
	}
	if v, ok := ipSendString(s, "ip-options"); ok {
		if err := rejectIPAncillaryApply("ip-options", family); err != nil {
			return err
		}
		if err := applyIPOptions(fd, v); err != nil {
			return fmt.Errorf("ip-options: %w", err)
		}
	}
	if n, ok, err := ipSendInt(s, "ipv6-unicast-hops"); err != nil {
		return fmt.Errorf("ipv6-unicast-hops: %w", err)
	} else if ok {
		if err := rejectIPAncillaryApply("ipv6-unicast-hops", family); err != nil {
			return err
		}
		if err := setSockoptInt(fd, ipLevelIPv6, ipOptUnicastHops, n); err != nil {
			return fmt.Errorf("ipv6-unicast-hops: %w", err)
		}
	}
	if n, ok, err := ipSendInt(s, "ipv6-tclass"); err != nil {
		return fmt.Errorf("ipv6-tclass: %w", err)
	} else if ok {
		if err := rejectIPAncillaryApply("ipv6-tclass", family); err != nil {
			return err
		}
		if err := applyIPv6Tclass(fd, n); err != nil {
			return fmt.Errorf("ipv6-tclass: %w", err)
		}
	}
	return nil
}

func ipSendInt(s parse.Spec, canonical string) (int, bool, error) {
	o, ok := s.OptionNamed(canonical)
	if !ok || !o.Has || strings.TrimSpace(o.Value) == "" {
		return 0, false, nil
	}
	n, err := ParseIntAny(o.Value)
	if err != nil {
		return 0, true, err
	}
	return n, true, nil
}

func ipSendString(s parse.Spec, canonical string) (string, bool) {
	o, ok := s.OptionNamed(canonical)
	if !ok || !o.Has {
		return "", false
	}
	v := strings.TrimSpace(o.Value)
	if v == "" {
		return "", false
	}
	return v, true
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
