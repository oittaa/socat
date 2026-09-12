package addrconfig

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// RangeForm is the static shape of a range= value.
type RangeForm uint8

const (
	RangeNone RangeForm = iota
	RangeAny
	RangeCIDR
	RangeExact
	RangeAddrMask
	RangeHex
)

// IPRange is the decoded range= syntax. Hostnames stay unresolved.
type IPRange struct {
	Form    RangeForm
	Prefix  netip.Prefix
	Host    HostTarget
	Mask    netip.Addr
	HexNet  []byte
	HexMask []byte
}

// ParseIPRange decodes range= syntax without DNS.
func ParseIPRange(spec string) (IPRange, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return IPRange{Form: RangeAny}, nil
	}

	if strings.Contains(spec, "/") {
		cidr := spec
		if i := strings.LastIndex(spec, "/"); i > 0 {
			addrPart := stripBrackets(spec[:i])
			cidr = addrPart + spec[i:]
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			_, network, cidrErr := net.ParseCIDR(cidr)
			if cidrErr != nil {
				return IPRange{}, fmt.Errorf("range: %w", err)
			}
			addr, ok := netip.AddrFromSlice(network.IP)
			if !ok {
				return IPRange{}, fmt.Errorf("range: %w", err)
			}
			ones, _ := network.Mask.Size()
			prefix = netip.PrefixFrom(addr, ones)
		}
		return IPRange{Form: RangeCIDR, Prefix: prefix}, nil
	}

	if strings.ContainsAny(spec, "xX") {
		if parsed, err, handled := parseHexSockRange(spec); handled {
			if err != nil {
				return IPRange{}, err
			}
			return parsed, nil
		}
	}

	if strings.HasPrefix(spec, "[") {
		if end := strings.Index(spec, "]"); end > 0 && end+1 < len(spec) && spec[end+1] == ':' {
			return parseAddrMask(spec[:end+1], spec[end+2:])
		}
	}

	if i := strings.LastIndex(spec, ":"); i > 0 {
		addrPart := spec[:i]
		maskPart := spec[i+1:]
		if strings.Count(maskPart, ".") == 3 {
			return parseAddrMask(addrPart, maskPart)
		}
	}

	return IPRange{Form: RangeExact, Host: targetFromText(spec)}, nil
}

func parseAddrMask(addrPart, maskPart string) (IPRange, error) {
	maskIP := net.ParseIP(stripBrackets(maskPart))
	mask, ok := netip.AddrFromSlice(maskIP)
	if !ok {
		return IPRange{}, fmt.Errorf("range: invalid addr:mask %s:%s", addrPart, maskPart)
	}
	if v4 := maskIP.To4(); v4 != nil {
		mask, _ = netip.AddrFromSlice(v4)
	}
	return IPRange{Form: RangeAddrMask, Host: targetFromText(addrPart), Mask: mask}, nil
}

func parseHexSockRange(spec string) (IPRange, error, bool) {
	idx := -1
	if i := strings.Index(strings.ToLower(spec), ":x"); i > 0 {
		idx = i
	} else if i := strings.LastIndex(spec, ":"); i > 0 {
		idx = i
	}
	if idx <= 0 {
		return IPRange{}, nil, false
	}
	netPart := spec[:idx]
	maskPart := spec[idx+1:]
	if !strings.ContainsAny(netPart, "xX") || !strings.ContainsAny(maskPart, "xX") {
		return IPRange{}, nil, false
	}
	netBytes, nerr := ParseSocatData(netPart)
	maskBytes, merr := ParseSocatData(maskPart)
	if nerr != nil || merr != nil {
		return IPRange{}, fmt.Errorf("range: invalid hex sockaddr"), true
	}
	if len(netBytes) < 6 || len(maskBytes) < 6 {
		return IPRange{}, fmt.Errorf("range: hex sockaddr too short"), true
	}
	if len(netBytes) >= 2+4+16 && len(maskBytes) < 2+4+16 {
		return IPRange{}, fmt.Errorf("range: IPv6 mask too short"), true
	}
	return IPRange{Form: RangeHex, HexNet: netBytes, HexMask: maskBytes}, nil, true
}
