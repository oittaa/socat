package addr

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

// peerAllowed implements classic xiocheckpeer-style filters for listen accepts:
// range, sourceport (as peer-port filter), and lowport.
// Returns nil if the peer is permitted.
func peerAllowed(s parse.Spec, conn net.Conn) error {
	if conn == nil {
		return nil
	}
	ra := conn.RemoteAddr()
	if ra == nil {
		return nil
	}

	host, portStr, err := net.SplitHostPort(ra.String())
	if err != nil {
		// Non-IP (e.g. unix) — range/sourceport/lowport do not apply.
		return nil
	}
	ip := net.ParseIP(stripBrackets(host))
	port := 0
	if portStr != "" {
		port, _ = strconv.Atoi(portStr)
	}

	if s.HasOption("range") {
		if ip == nil {
			return fmt.Errorf("range: peer has no IP")
		}
		ok, perr := ipInRange(ip, s.OptionValue("range", ""))
		if perr != nil {
			return perr
		}
		if !ok {
			return fmt.Errorf("refusing connection from %s, not in range", ra)
		}
	}

	// On listen, sourceport/sp is a peer filter (not bind).
	if s.HasOption("sourceport") {
		want := s.OptionValue("sourceport", "")
		if want != "" && portStr != want {
			return fmt.Errorf("refusing connection from %s, sourceport mismatch", ra)
		}
	}

	if s.BoolOption("lowport") {
		if port == 0 || port >= 1024 {
			return fmt.Errorf("refusing connection from %s, not a low port", ra)
		}
	}

	return nil
}

// ipInRange parses classic range syntax:
//
//	addr/bits          CIDR
//	addr:netmask       IPv4 (or IPv6 with mask as address)
//	[ipv6]/bits
func ipInRange(ip net.IP, spec string) (bool, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return true, nil
	}

	// CIDR: addr/bits (IPv6 may be bracketed)
	if strings.Contains(spec, "/") {
		// Allow [addr]/bits
		cidr := spec
		if i := strings.LastIndex(spec, "/"); i > 0 {
			addrPart := stripBrackets(spec[:i])
			cidr = addrPart + spec[i:]
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return false, fmt.Errorf("range: %w", err)
		}
		return network.Contains(ip), nil
	}

	// addr:mask — split on last ':' that is not part of IPv6 ambiguity carefully.
	// Classic IPv4 uses a.b.c.d:w.x.y.z. IPv6 range without / usually uses brackets.
	if strings.HasPrefix(spec, "[") {
		// [ipv6]:mask — uncommon; try split after ]
		if end := strings.Index(spec, "]"); end > 0 && end+1 < len(spec) && spec[end+1] == ':' {
			addrPart := stripBrackets(spec[:end+1])
			maskPart := spec[end+2:]
			return matchAddrMask(ip, addrPart, maskPart)
		}
	}

	// IPv4 a.b.c.d:w.x.y.z — exactly one colon between two dotted quads
	if parts := strings.Split(spec, ":"); len(parts) == 2 &&
		strings.Count(parts[0], ".") == 3 && strings.Count(parts[1], ".") == 3 {
		return matchAddrMask(ip, parts[0], parts[1])
	}

	// Bare address = /32 or /128
	base := net.ParseIP(stripBrackets(spec))
	if base == nil {
		return false, fmt.Errorf("range: invalid %q", spec)
	}
	if base.Equal(ip) {
		return true, nil
	}
	return false, nil
}

func matchAddrMask(ip net.IP, addrPart, maskPart string) (bool, error) {
	base := net.ParseIP(stripBrackets(addrPart))
	maskIP := net.ParseIP(stripBrackets(maskPart))
	if base == nil || maskIP == nil {
		return false, fmt.Errorf("range: invalid addr:mask %s:%s", addrPart, maskPart)
	}
	// Use IPv4 forms when both are v4.
	if b4, m4 := base.To4(), maskIP.To4(); b4 != nil && m4 != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			return false, nil
		}
		for i := 0; i < 4; i++ {
			if ip4[i]&m4[i] != b4[i]&m4[i] {
				return false, nil
			}
		}
		return true, nil
	}
	b16 := base.To16()
	m16 := maskIP.To16()
	ip16 := ip.To16()
	if b16 == nil || m16 == nil || ip16 == nil {
		return false, nil
	}
	for i := 0; i < 16; i++ {
		if ip16[i]&m16[i] != b16[i]&m16[i] {
			return false, nil
		}
	}
	return true, nil
}
