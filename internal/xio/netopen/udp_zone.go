package netopen

import (
	"fmt"
	"net"
	"strconv"

	"github.com/oittaa/socat/internal/xio"
)

// udpPeer is a UDP session endpoint.
// scope is a kernel sin6_scope_id. When it is non-zero, Zone is not a name
// and is not used to choose the interface.
type udpPeer struct {
	*net.UDPAddr
	scope uint32
}

func (p *udpPeer) Network() string {
	if p == nil || p.UDPAddr == nil {
		return "udp"
	}
	return p.UDPAddr.Network()
}

func (p *udpPeer) String() string {
	if p == nil || p.UDPAddr == nil {
		return "<nil>"
	}
	if p.scope == 0 {
		return p.UDPAddr.String()
	}
	shown := *p.UDPAddr
	shown.Zone = strconv.FormatUint(uint64(p.scope), 10)
	return shown.String()
}

func udpPeerFromNet(a *net.UDPAddr) *udpPeer {
	if a == nil {
		return nil
	}
	return &udpPeer{UDPAddr: cloneUDPAddr(a)}
}

func cloneUDPPeer(p *udpPeer) *udpPeer {
	if p == nil {
		return nil
	}
	return &udpPeer{UDPAddr: cloneUDPAddr(p.UDPAddr), scope: p.scope}
}

// udpZoneMatch reports whether two user-supplied IPv6 zones name the same
// scope. An empty zone matches only another empty zone. A name and a numeric
// index match when they refer to the same interface.
func udpZoneMatch(a, b string) bool {
	if a == b {
		return true
	}
	if a == "" || b == "" {
		return false
	}
	ia, aOK := udpZoneIndex(a)
	ib, bOK := udpZoneIndex(b)
	return aOK && bOK && ia == ib
}

// udpZoneIndex resolves user-supplied zone text.
// An interface name is tried before a numeric index.
func udpZoneIndex(zone string) (int, bool) {
	if ifi, err := net.InterfaceByName(zone); err == nil && ifi.Index > 0 {
		return ifi.Index, true
	}
	if n, err := strconv.Atoi(zone); err == nil && n > 0 {
		return n, true
	}
	return 0, false
}

// ipv6ScopeID resolves user-supplied zone text to an interface index.
// An interface name is tried before a numeric index.
func ipv6ScopeID(zone string) (uint32, error) {
	if zone == "" {
		return 0, nil
	}
	ifi, nameErr := net.InterfaceByName(zone)
	if nameErr == nil {
		index, ok := xio.Uint32FromInt(ifi.Index)
		if !ok || index == 0 {
			return 0, fmt.Errorf("zone %q: interface index %d out of range", zone, ifi.Index)
		}
		return index, nil
	}
	id, err := strconv.ParseUint(zone, 10, 32)
	if err == nil {
		if id == 0 {
			return 0, fmt.Errorf("zone %q: invalid interface index", zone)
		}
		return uint32(id), nil
	}
	return 0, fmt.Errorf("zone %q: %w", zone, nameErr)
}

func udpScopeMatch(a, b *udpPeer) bool {
	if a == nil || b == nil {
		return false
	}
	if a.scope != 0 && b.scope != 0 {
		return a.scope == b.scope
	}
	if a.scope != 0 {
		return userZoneIsScope(zoneText(b), a.scope)
	}
	if b.scope != 0 {
		return userZoneIsScope(zoneText(a), b.scope)
	}
	return udpZoneMatch(zoneText(a), zoneText(b))
}

func zoneText(p *udpPeer) string {
	if p == nil || p.UDPAddr == nil {
		return ""
	}
	return p.Zone
}

func userZoneIsScope(zone string, scope uint32) bool {
	if zone == "" || scope == 0 {
		return false
	}
	idx, ok := udpZoneIndex(zone)
	if !ok {
		return false
	}
	id, ok := xio.Uint32FromInt(idx)
	return ok && id == scope
}
