package netopen

import (
	"net"
	"strconv"
	"sync"
)

// Successful index-to-name lookups are cached. A failed lookup is not, so a
// later attempt can still resolve the interface.
var (
	zoneNameCache  sync.Map // int -> string
	zoneIndexCache sync.Map // string -> int
)

func interfaceNameByIndex(index int) (string, error) {
	if name, ok := zoneNameCache.Load(index); ok {
		return name.(string), nil
	}
	ifi, err := net.InterfaceByIndex(index)
	if err != nil {
		return "", err
	}
	zoneNameCache.Store(index, ifi.Name)
	zoneIndexCache.Store(ifi.Name, index)
	return ifi.Name, nil
}

// udpZoneMatch reports whether two IPv6 zones name the same scope.
// An empty zone matches only another empty zone. A name and a numeric
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

func udpZoneIndex(zone string) (int, bool) {
	if n, err := strconv.Atoi(zone); err == nil && n > 0 {
		return n, true
	}
	if v, ok := zoneIndexCache.Load(zone); ok {
		return v.(int), true
	}
	ifi, err := net.InterfaceByName(zone)
	if err != nil || ifi.Index <= 0 {
		return 0, false
	}
	zoneIndexCache.Store(zone, ifi.Index)
	zoneNameCache.Store(ifi.Index, ifi.Name)
	return ifi.Index, true
}
