package xio

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

// CloseRefusedPeer closes a rejected accept without RST when the peer already
// wrote (unread data would otherwise trigger connection reset). Empty client
// output / exit 0, not "connection reset by peer".
func CloseRefusedPeer(c net.Conn) {
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

// PeerFilter holds parsed peer policy for one address lifetime.
type PeerFilter struct {
	spec          parse.Spec
	hasRange      bool
	rangeSpec     string
	rangeOnce     sync.Once
	rangeMatcher  ipRangeMatcher
	rangeErr      error
	hasSourcePort bool
	sourcePort    string
	lowport       bool
	tcpwrap       tcpwrapConfig
}

// NewPeerFilter parses peer policy that does not depend on the remote address.
func NewPeerFilter(s parse.Spec, g *Global) *PeerFilter {
	_, hasRange := s.OptionNamed("range")
	_, hasSourcePort := s.OptionNamed("sourceport")
	return &PeerFilter{
		spec:          s,
		hasRange:      hasRange,
		rangeSpec:     s.OptionValue("range", ""),
		hasSourcePort: hasSourcePort,
		sourcePort:    s.OptionValue("sourceport", ""),
		lowport:       s.BoolOption("lowport"),
		tcpwrap:       parseTCPWrap(s, g),
	}
}

// PeerAllowedG checks a connection with a one-use filter. Long-lived callers
// should keep a PeerFilter instead.
func PeerAllowedG(s parse.Spec, conn net.Conn, g *Global) error {
	return NewPeerFilter(s, g).AllowConn(conn)
}

func (f *PeerFilter) AllowConn(conn net.Conn) error {
	if conn == nil {
		return nil
	}
	return f.AllowAddr(conn.RemoteAddr(), conn.LocalAddr())
}

// AllowAddr checks one peer without constructing a temporary net.Conn.
func (f *PeerFilter) AllowAddr(remote, local net.Addr) error {
	if f == nil || remote == nil {
		return nil
	}

	ip, port, portStr, isIP := peerIPPort(remote)
	if !isIP {
		// Non-IP (e.g. unix) — range/sourceport/lowport do not apply.
		// Still run tcpwrap if enabled (unlikely for unix).
		if f.tcpwrap.enabled {
			return tcpwrapAllowedForSpec(f.spec, f.tcpwrap, remote, local)
		}
		return nil
	}

	if f.hasRange {
		if ip == nil {
			return fmt.Errorf("range: peer has no IP")
		}
		f.rangeOnce.Do(func() {
			f.rangeMatcher, f.rangeErr = compileIPRange(f.rangeSpec, LookupResolver(f.spec))
		})
		if f.rangeErr != nil {
			return f.rangeErr
		}
		if !f.rangeMatcher(ip) {
			return fmt.Errorf("refusing connection from %s, not in range", remote)
		}
	}

	// On listen, sourceport/sp is a peer filter (not bind).
	if f.hasSourcePort {
		if portStr == "" {
			portStr = strconv.Itoa(port)
		}
		if f.sourcePort != "" && portStr != f.sourcePort {
			return fmt.Errorf("refusing connection from %s, sourceport mismatch", remote)
		}
	}

	if f.lowport {
		if port == 0 || port >= 1024 {
			return fmt.Errorf("refusing connection from %s, not a low port", remote)
		}
	}

	if f.tcpwrap.enabled {
		if err := tcpwrapAllowedForSpec(f.spec, f.tcpwrap, remote, local); err != nil {
			return err
		}
	}

	return nil
}

func peerIPPort(addr net.Addr) (net.IP, int, string, bool) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP, a.Port, "", true
	case *net.TCPAddr:
		return a.IP, a.Port, "", true
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, 0, "", false
	}
	port, _ := strconv.Atoi(portStr)
	return net.ParseIP(StripBrackets(host)), port, portStr, true
}

type ipRangeMatcher func(net.IP) bool

// ipInRange parses range syntax:
//
//	addr/bits          CIDR
//	addr:netmask       IPv4 (or IPv6 with mask as address)
//	[ipv6]/bits
//	xPORTxIP:xPORTxMASK  SOCKET hex (port prefix ignored)
func ipInRange(ip net.IP, spec string) (bool, error) {
	return ipInRangeWithResolver(ip, spec, net.DefaultResolver)
}

func ipInRangeWithResolver(ip net.IP, spec string, resolver *net.Resolver) (bool, error) {
	matcher, err := compileIPRange(spec, resolver)
	if err != nil {
		return false, err
	}
	return matcher(ip), nil
}

func compileIPRange(spec string, resolver *net.Resolver) (ipRangeMatcher, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return func(net.IP) bool { return true }, nil
	}

	// CIDR: addr/bits (IPv6 may be bracketed)
	if strings.Contains(spec, "/") {
		// Allow [addr]/bits
		cidr := spec
		if i := strings.LastIndex(spec, "/"); i > 0 {
			addrPart := StripBrackets(spec[:i])
			cidr = addrPart + spec[i:]
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("range: %w", err)
		}
		return network.Contains, nil
	}

	// SOCKET hex: x0000x7f000000:x0000xffffffff (sockaddr data net:mask)
	if strings.Contains(spec, "x") || strings.Contains(spec, "X") {
		if matcher, err, handled := compileHexSockRange(spec); handled {
			return matcher, err
		}
	}

	// addr:mask — split on last ':' that is not part of IPv6 ambiguity carefully.
	// IPv4 uses a.b.c.d:w.x.y.z. IPv6 range without / usually uses brackets.
	if strings.HasPrefix(spec, "[") {
		// [ipv6]:mask — uncommon; try split after ]
		if end := strings.Index(spec, "]"); end > 0 && end+1 < len(spec) && spec[end+1] == ':' {
			addrPart := StripBrackets(spec[:end+1])
			maskPart := spec[end+2:]
			return compileAddrMask(addrPart, maskPart, resolver)
		}
	}

	// IPv4: a.b.c.d:w.x.y.z or hostname:w.x.y.z.
	// Prefer last-colon split when the right side looks like an IPv4 mask (three dots).
	if i := strings.LastIndex(spec, ":"); i > 0 {
		addrPart := StripBrackets(spec[:i])
		maskPart := spec[i+1:]
		if strings.Count(maskPart, ".") == 3 {
			return compileAddrMask(addrPart, maskPart, resolver)
		}
	}

	// Bare address or hostname = exact host (/32 or /128 after resolve).
	base := net.ParseIP(StripBrackets(spec))
	if base == nil {
		ips, err := resolver.LookupIP(context.Background(), "ip", StripBrackets(spec))
		if err != nil {
			return nil, fmt.Errorf("range: invalid %q", spec)
		}
		return func(ip net.IP) bool {
			for _, cand := range ips {
				if cand.Equal(ip) {
					return true
				}
			}
			return false
		}, nil
	}
	return base.Equal, nil
}

func compileHexSockRange(spec string) (matcher ipRangeMatcher, err error, handled bool) {
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
		return nil, nil, false
	}
	netPart := spec[:idx]
	maskPart := spec[idx+1:]
	if !strings.ContainsAny(netPart, "xX") || !strings.ContainsAny(maskPart, "xX") {
		return nil, nil, false
	}
	netBytes, nerr := ParseSocatData(netPart)
	maskBytes, merr := ParseSocatData(maskPart)
	if nerr != nil || merr != nil {
		return nil, fmt.Errorf("range: invalid hex sockaddr"), true
	}
	if len(netBytes) < 6 || len(maskBytes) < 6 {
		return nil, fmt.Errorf("range: hex sockaddr too short"), true
	}
	// Skip 2-byte port prefix; next 4 bytes are IPv4.
	// If longer (>= 22 after port+flow), treat as IPv6.
	if len(netBytes) >= 2+4+16 {
		// IPv6: port(2)+flow(4)+addr(16)
		if len(maskBytes) < 2+4+16 {
			return nil, fmt.Errorf("range: IPv6 mask too short"), true
		}
		base := net.IP(netBytes[6:22])
		mask := net.IP(maskBytes[6:22])
		return maskedIPMatcher([]net.IP{base}, mask), nil, true
	}
	// IPv4
	base := net.IPv4(netBytes[2], netBytes[3], netBytes[4], netBytes[5])
	mask := net.IPv4(maskBytes[2], maskBytes[3], maskBytes[4], maskBytes[5])
	return maskedIPMatcher([]net.IP{base}, mask), nil, true
}

func compileAddrMask(addrPart, maskPart string, resolver *net.Resolver) (ipRangeMatcher, error) {
	base := net.ParseIP(StripBrackets(addrPart))
	bases := []net.IP{base}
	if base == nil {
		ips, err := resolver.LookupIP(context.Background(), "ip", StripBrackets(addrPart))
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("range: resolve %s: %v", addrPart, err)
		}
		bases = ips
	}
	maskIP := net.ParseIP(StripBrackets(maskPart))
	if maskIP == nil {
		return nil, fmt.Errorf("range: invalid addr:mask %s:%s", addrPart, maskPart)
	}
	return maskedIPMatcher(bases, maskIP), nil
}

func maskedIPMatcher(bases []net.IP, mask net.IP) ipRangeMatcher {
	return func(ip net.IP) bool {
		var base net.IP
		want4 := ip.To4() != nil
		for _, cand := range bases {
			if (cand.To4() != nil) == want4 {
				base = cand
				break
			}
		}
		if base == nil && len(bases) > 0 {
			base = bases[0]
		}
		if b4, m4 := base.To4(), mask.To4(); b4 != nil && m4 != nil {
			ip4 := ip.To4()
			if ip4 == nil {
				return false
			}
			for i := 0; i < 4; i++ {
				if ip4[i]&m4[i] != b4[i]&m4[i] {
					return false
				}
			}
			return true
		}
		b16, m16, ip16 := base.To16(), mask.To16(), ip.To16()
		if b16 == nil || m16 == nil || ip16 == nil {
			return false
		}
		for i := 0; i < 16; i++ {
			if ip16[i]&m16[i] != b16[i]&m16[i] {
				return false
			}
		}
		return true
	}
}
