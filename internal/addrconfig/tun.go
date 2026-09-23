package addrconfig

import (
	"fmt"
	"net/netip"
	"strings"
)

func decodeTUNPositional(a *Address) error {
	n := 0
	for _, p := range a.Params {
		if p != "" {
			n++
		}
	}
	if n > 1 || len(a.Params) > 1 {
		return parameterCountError(len(a.Params), 0, 1)
	}
	if len(a.Params) == 0 || a.Params[0] == "" {
		return nil
	}
	value := a.Params[0]
	if !strings.Contains(value, "/") {
		value += "/24"
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() {
		return fmt.Errorf("TUN address %q: IPv4 required", a.Params[0])
	}
	a.Network.TUNAddress, a.Network.TUNAddressSet = prefix, true
	return nil
}

func interfaceFlagBit(name string) (uint16, bool) {
	flags := map[string]uint16{
		"iff-up":          0x1,
		"iff-broadcast":   0x2,
		"iff-debug":       0x4,
		"iff-loopback":    0x8,
		"iff-pointopoint": 0x10,
		"iff-notrailers":  0x20,
		"iff-running":     0x40,
		"iff-noarp":       0x80,
		"iff-promisc":     0x100,
		"iff-allmulti":    0x200,
		"iff-master":      0x400,
		"iff-slave":       0x800,
		"iff-multicast":   0x1000,
		"iff-portsel":     0x2000,
		"iff-automedia":   0x4000,
	}
	bit, ok := flags[name]
	return bit, ok
}
