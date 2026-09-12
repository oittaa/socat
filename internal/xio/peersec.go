package xio

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
)

// CloseRefusedPeer closes a rejected accept without RST when the peer already
// wrote (unread data would otherwise trigger connection reset). Empty client
// output / exit 0, not "connection reset by peer".
func CloseRefusedPeer(c net.Conn) {
	if c == nil {
		return
	}
	// Walk nested NetConn wrappers (TLS → SocketTimeoutConn → TCPConn)
	// so the TCP socket is drained. WebSocket connections stay opaque:
	// wsNetConn does not implement NetConn().
	raw := unwrapNetConn(c)
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		_, _ = io.Copy(io.Discard, tc)
		_ = tc.CloseWrite()
	}
	_ = c.Close()
}

// PeerFilter holds parsed peer policy for one address lifetime.
type PeerFilter struct {
	ctx           context.Context
	resolver      *net.Resolver
	hasRange      bool
	rangeMatcher  ipRangeMatcher
	hasSourcePort bool
	sourcePort    addrconfig.PortTarget
	lowport       bool
	tcpwrap       tcpwrapConfig
}

// PreparedPeerFilter compiles the prepared peer policy for an opening.
func PreparedPeerFilter(ctx context.Context, config addrconfig.Address, opts Options) (*PeerFilter, error) {
	return NewPeerFilter(ctx, config.Network, LookupResolver(config), opts)
}

// NewPeerFilter compiles peer policy and resolves range= once. Callers must
// construct it before accepting or receiving peers so syntax and lookup
// errors abort the address instead of leaving a listener that rejects every
// peer. ctx cancels hostname range compilation; tcpwrap reverse DNS still
// uses it per peer. Long-lived listeners pass the session context so
// shutdown does not leave lookups running.
func NewPeerFilter(ctx context.Context, policy addrconfig.Network, resolver *net.Resolver, opts Options) (*PeerFilter, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	f := &PeerFilter{
		ctx:           ctx,
		resolver:      resolver,
		hasRange:      policy.RangeSet,
		hasSourcePort: policy.SourcePortSet,
		sourcePort:    policy.SourcePort,
		lowport:       policy.LowPort.Value,
		tcpwrap:       parseTCPWrap(policy, opts),
	}
	if policy.RangeSet {
		matcher, err := compileIPRange(ctx, policy.Range, resolver)
		if err != nil {
			return nil, err
		}
		f.rangeMatcher = matcher
	}
	return f, nil
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
	ctx := f.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	ip, port, portStr, isIP := peerIPPort(remote)
	if !isIP {
		// Non-IP (e.g. unix) — range/sourceport/lowport do not apply.
		// Still run tcpwrap if enabled (unlikely for unix).
		if f.tcpwrap.enabled {
			return tcpwrapAllowedWithResolver(ctx, f.resolver, f.tcpwrap, remote, local)
		}
		return nil
	}

	if f.hasRange {
		if ip == nil {
			return fmt.Errorf("range: peer has no IP")
		}
		if f.rangeMatcher == nil || !f.rangeMatcher(ip) {
			return fmt.Errorf("refusing connection from %s, not in range", remote)
		}
	}

	// On listen, sourceport/sp is a peer filter (not bind).
	if f.hasSourcePort && !sourcePortMatches(f.sourcePort, port, portStr) {
		return fmt.Errorf("refusing connection from %s, sourceport mismatch", remote)
	}

	if f.lowport {
		if port == 0 || port >= 1024 {
			return fmt.Errorf("refusing connection from %s, not a low port", remote)
		}
	}

	if f.tcpwrap.enabled {
		if err := tcpwrapAllowedWithResolver(ctx, f.resolver, f.tcpwrap, remote, local); err != nil {
			return err
		}
	}

	return nil
}

func sourcePortMatches(want addrconfig.PortTarget, port int, portStr string) bool {
	if want.Numeric {
		return port == int(want.Number)
	}
	if want.Service == "" {
		return true
	}
	if portStr == "" {
		portStr = strconv.Itoa(port)
	}
	return portStr == want.Service
}

func peerIPPort(addr net.Addr) (net.IP, int, string, bool) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP, a.Port, "", true
	case *net.TCPAddr:
		return a.IP, a.Port, "", true
	case *net.IPAddr:
		if a == nil {
			return nil, 0, "", false
		}
		return a.IP, 0, "", true
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, 0, "", false
	}
	port, _ := strconv.Atoi(portStr)
	return net.ParseIP(StripBrackets(host)), port, portStr, true
}

type ipRangeMatcher func(net.IP) bool

func compileIPRange(ctx context.Context, spec addrconfig.IPRange, resolver *net.Resolver) (ipRangeMatcher, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	switch spec.Form {
	case addrconfig.RangeNone, addrconfig.RangeAny:
		return func(net.IP) bool { return true }, nil
	case addrconfig.RangeCIDR:
		return compileCIDRMatcher(spec.Prefix), nil
	case addrconfig.RangeHex:
		return compileHexSockRange(spec.HexNet, spec.HexMask)
	case addrconfig.RangeAddrMask:
		return compileAddrMask(ctx, spec.Host, spec.Mask, resolver)
	case addrconfig.RangeExact:
		if spec.Host.IsLiteral() {
			base := spec.Host.IP()
			return base.Equal, nil
		}
		ips, err := rangeLookupIPs(ctx, resolver.LookupIP, StripBrackets(spec.Host.Name))
		if err != nil {
			return nil, fmt.Errorf("range: %w", err)
		}
		return func(ip net.IP) bool {
			for _, cand := range ips {
				if cand.Equal(ip) {
					return true
				}
			}
			return false
		}, nil
	default:
		return func(net.IP) bool { return true }, nil
	}
}

func compileHexSockRange(netBytes, maskBytes []byte) (ipRangeMatcher, error) {
	if len(netBytes) >= 2+4+16 {
		if len(maskBytes) < 2+4+16 {
			return nil, fmt.Errorf("range: IPv6 mask too short")
		}
		base := net.IP(netBytes[6:22])
		mask := net.IP(maskBytes[6:22])
		return maskedIPMatcher([]net.IP{base}, mask), nil
	}
	base := net.IPv4(netBytes[2], netBytes[3], netBytes[4], netBytes[5])
	mask := net.IPv4(maskBytes[2], maskBytes[3], maskBytes[4], maskBytes[5])
	return maskedIPMatcher([]net.IP{base}, mask), nil
}

func compileAddrMask(ctx context.Context, addr addrconfig.HostTarget, mask netip.Addr, resolver *net.Resolver) (ipRangeMatcher, error) {
	var bases []net.IP
	if addr.IsLiteral() {
		bases = []net.IP{addr.IP()}
	} else {
		ips, err := rangeLookupIPs(ctx, resolver.LookupIP, StripBrackets(addr.Name))
		if err != nil {
			return nil, fmt.Errorf("range: resolve %s: %w", addr.Name, err)
		}
		bases = ips
	}
	return maskedIPMatcher(bases, net.IP(mask.AsSlice())), nil
}

func compileCIDRMatcher(prefix netip.Prefix) ipRangeMatcher {
	n := &net.IPNet{
		IP:   net.IP(prefix.Addr().AsSlice()),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}
	return n.Contains
}

func rangeLookupIPs(ctx context.Context, lookup func(context.Context, string, string) ([]net.IP, error), host string) ([]net.IP, error) {
	ips, err := lookup(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %q", host)
	}
	return ips, nil
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
