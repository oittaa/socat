package addrconfig

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/oittaa/socat/internal/parse"
)

func decodeTUNPositional(a *Address) error {
	n := 0
	for _, p := range a.Params {
		if p != "" {
			n++
		}
	}
	if n > 1 || len(a.Params) > 1 {
		return fmt.Errorf("too many parameters (%d instead of 0 or 1)", len(a.Params))
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

func decodeTUNOption(n *Network, o parse.Option, name string) (bool, error) {
	switch name {
	case "tun-device", "tun-name":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		if name == "tun-device" {
			n.TUNDevice = value
		} else {
			n.TUNName = value
		}
	case "tun-type":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		switch strings.ToLower(value) {
		case "tun":
			n.TUNType = TUNTypeTUN
		case "tap":
			n.TUNType = TUNTypeTAP
		default:
			return true, fmt.Errorf("unknown tun-type %q", value)
		}
	case "iff-no-pi":
		v, err := optionalBool(o)
		if err != nil {
			return true, err
		}
		n.TUNNoPacketInfo = v
	case "if-mtu":
		value, err := requiredString(o)
		if err != nil {
			return true, err
		}
		mtu, err := strconv.ParseUint(value, 0, 32)
		if err != nil || mtu == 0 {
			return true, fmt.Errorf("if-mtu: invalid %q", value)
		}
		n.TUNMTU = OptionalUint32{Set: true, Value: uint32(mtu)}
	case "retrieve-vlan":
		if o.Has {
			return true, fmt.Errorf("%s: no value permitted", o.OriginalSpelling())
		}
		n.TUNRetrieveVLAN = true
	default:
		bit, ok := interfaceFlagBit(name)
		if !ok {
			return false, nil
		}
		v, err := optionalBool(o)
		if err != nil {
			return true, err
		}
		if v.Value {
			n.TUNInterfaceSet |= bit
			n.TUNInterfaceClr &^= bit
		} else {
			n.TUNInterfaceClr |= bit
			n.TUNInterfaceSet &^= bit
		}
	}
	return true, nil
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
