package netopen

import (
	"fmt"
	"net"
	"strconv"

	"github.com/oittaa/socat/internal/xio"
)

// lookupInterface resolves a zone name. Tests replace it.
var lookupInterface = net.InterfaceByName

// udpZoneMatch reports whether two IPv6 zones name the same scope.
// An empty zone matches only another empty zone. A name and a numeric
// index match when they refer to the same interface.
// Fork-session routing uses this comparison.
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

// udpZoneIndex resolves a zone for fork-session matching.
// An interface name is tried before a numeric index.
func udpZoneIndex(zone string) (int, bool) {
	if ifi, err := lookupInterface(zone); err == nil && ifi.Index > 0 {
		return ifi.Index, true
	}
	if n, err := strconv.Atoi(zone); err == nil && n > 0 {
		return n, true
	}
	return 0, false
}

// ipv6ScopeID resolves a zone to an interface index for a socket address.
// An interface name is tried before a numeric index.
func ipv6ScopeID(zone string) (uint32, error) {
	if zone == "" {
		return 0, nil
	}
	ifi, nameErr := lookupInterface(zone)
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
