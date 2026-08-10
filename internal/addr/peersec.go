package addr

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

// closeRefusedPeer closes a rejected accept without RST when the peer already
// wrote (unread data would otherwise trigger connection reset). Classic security
// tests expect empty client output / exit 0, not "connection reset by peer".
func closeRefusedPeer(c net.Conn) {
	if c == nil {
		return
	}
	// Unwrap TLS so we can drain the TCP socket.
	type netConner interface{ NetConn() net.Conn }
	raw := c
	if nc, ok := c.(netConner); ok {
		if inner := nc.NetConn(); inner != nil {
			raw = inner
		}
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		_, _ = io.Copy(io.Discard, tc)
		_ = tc.CloseWrite()
	}
	_ = c.Close()
}

// peerAllowed implements classic xiocheckpeer-style filters for listen accepts:
// range, sourceport (as peer-port filter), lowport, and tcpwrap/libwrap.
// Returns nil if the peer is permitted.
// g may be nil; when non-nil it supplies progname for tcpwrap daemon name.
func peerAllowed(s parse.Spec, conn net.Conn) error {
	return peerAllowedG(s, conn, nil)
}

func peerAllowedG(s parse.Spec, conn net.Conn, g *Global) error {
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
		// Still run tcpwrap if enabled (unlikely for unix).
		if tw := parseTCPWrap(s, g); tw.enabled {
			return tcpwrapAllowed(tw, ra, conn.LocalAddr())
		}
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

	// TCP wrappers (hosts.allow / hosts.deny).
	if tw := parseTCPWrap(s, g); tw.enabled {
		if err := tcpwrapAllowed(tw, ra, conn.LocalAddr()); err != nil {
			return err
		}
	}

	return nil
}

// ipInRange parses classic range syntax:
//
//	addr/bits          CIDR
//	addr:netmask       IPv4 (or IPv6 with mask as address)
//	[ipv6]/bits
//	xPORTxIP:xPORTxMASK  classic generic SOCKET hex (port prefix ignored)
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

	// Classic SOCKET hex: x0000x7f000000:x0000xffffffff (sockaddr data net:mask)
	if strings.Contains(spec, "x") || strings.Contains(spec, "X") {
		if ok, err, handled := ipInHexSockRange(ip, spec); handled {
			return ok, err
		}
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

	// Classic IPv4: a.b.c.d:w.x.y.z or hostname:w.x.y.z (FDLEAK uses range=localhost:255.255.255.255).
	// Prefer last-colon split when the right side looks like an IPv4 mask (three dots).
	if i := strings.LastIndex(spec, ":"); i > 0 {
		addrPart := stripBrackets(spec[:i])
		maskPart := spec[i+1:]
		if strings.Count(maskPart, ".") == 3 {
			return matchAddrMask(ip, addrPart, maskPart)
		}
	}

	// Bare address or hostname = exact host (/32 or /128 after resolve).
	base := net.ParseIP(stripBrackets(spec))
	if base == nil {
		// Resolve hostname once for exact match.
		if ips, err := net.LookupIP(stripBrackets(spec)); err == nil {
			for _, cand := range ips {
				if cand.Equal(ip) {
					return true, nil
				}
			}
			return false, nil
		}
		return false, fmt.Errorf("range: invalid %q", spec)
	}
	if base.Equal(ip) {
		return true, nil
	}
	return false, nil
}

// ipInHexSockRange parses xPORTxIP:xPORTxMASK (classic generic socket range).
// handled=false if the form does not look like hex sockaddr range.
func ipInHexSockRange(ip net.IP, spec string) (ok bool, err error, handled bool) {
	// Split net:mask on the colon that separates the two hex groups.
	// Each side typically looks like x0000x7f000000 (port + IPv4) or longer for IPv6.
	idx := -1
	// Prefer split after first complete hex group: find ":x" which starts the mask side.
	if i := strings.Index(strings.ToLower(spec), ":x"); i > 0 {
		idx = i
	} else if i := strings.LastIndex(spec, ":"); i > 0 {
		idx = i
	}
	if idx <= 0 {
		return false, nil, false
	}
	netPart := spec[:idx]
	maskPart := spec[idx+1:]
	if !strings.ContainsAny(netPart, "xX") || !strings.ContainsAny(maskPart, "xX") {
		return false, nil, false
	}
	netBytes, nerr := parseSocatData(netPart)
	maskBytes, merr := parseSocatData(maskPart)
	if nerr != nil || merr != nil {
		return false, fmt.Errorf("range: invalid hex sockaddr"), true
	}
	if len(netBytes) < 6 || len(maskBytes) < 6 {
		return false, fmt.Errorf("range: hex sockaddr too short"), true
	}
	// Skip 2-byte port prefix; next 4 bytes are IPv4 (classic SOCKETRANGEMASK).
	// If longer (>= 22 after port+flow), treat as IPv6.
	if len(netBytes) >= 2+4+16 {
		// IPv6: port(2)+flow(4)+addr(16)
		if len(maskBytes) < 2+4+16 {
			return false, fmt.Errorf("range: IPv6 mask too short"), true
		}
		base := net.IP(netBytes[6:22])
		mask := net.IP(maskBytes[6:22])
		ok, err = matchAddrMask(ip, base.String(), mask.String())
		return ok, err, true
	}
	// IPv4
	base := net.IPv4(netBytes[2], netBytes[3], netBytes[4], netBytes[5])
	mask := net.IPv4(maskBytes[2], maskBytes[3], maskBytes[4], maskBytes[5])
	ok, err = matchAddrMask(ip, base.String(), mask.String())
	return ok, err, true
}

func matchAddrMask(ip net.IP, addrPart, maskPart string) (bool, error) {
	base := net.ParseIP(stripBrackets(addrPart))
	if base == nil {
		// Hostname in range= (classic range=localhost:255.255.255.255).
		ips, err := net.LookupIP(stripBrackets(addrPart))
		if err != nil || len(ips) == 0 {
			return false, fmt.Errorf("range: resolve %s: %v", addrPart, err)
		}
		// Prefer IPv4 base when peer is IPv4 (and vice versa).
		want4 := ip.To4() != nil
		for _, cand := range ips {
			if (cand.To4() != nil) == want4 {
				base = cand
				break
			}
		}
		if base == nil {
			base = ips[0]
		}
	}
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
