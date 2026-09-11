package xio

import (
	"fmt"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/optionmeta"
)

// Linux IPPROTO_RAW. IP4-SENDTO:host:255 uses this protocol;
// IP_ROUTER_ALERT returns EINVAL there (not a silent no-op).
const ipprotoRaw = 255

func getOnlyKernelName(name string) string {
	if def, ok := optionmeta.Lookup(name); ok && def.Kernel != "" {
		return def.Kernel
	}
	return name
}

func getOnlyNames(action addrconfig.SocketAction) (spelling, kernel string) {
	canonical := "ip-mtu"
	if action.GetOnly == addrconfig.IPGetOnlyPktoptions {
		canonical = "ip-pktoptions"
	}
	spelling = canonical
	if action.Text != "" {
		spelling = action.Text
	}
	return spelling, getOnlyKernelName(canonical)
}

func rejectPreparedRouterAlert(config addrconfig.Address, action addrconfig.SocketAction) error {
	spelling := action.Text
	if spelling == "" {
		spelling = "ip-router-alert"
	}
	if !isRawIPAddress(config) {
		typ := config.Type
		if typ == "" {
			return fmt.Errorf("%s: not supported with this address type", spelling)
		}
		return fmt.Errorf("%s: option %q not supported with this address type", typ, spelling)
	}
	family := preparedForcedIPFamily(config)
	if family == ipFamilyV6 {
		return fmt.Errorf("%s: option %q not supported on IPv6", config.Type, spelling)
	}
	if proto, ok := preparedRawIPProtocolNumber(config); ok && proto == ipprotoRaw {
		return fmt.Errorf("%s: option %q is not supported on IPPROTO_RAW sockets", config.Type, spelling)
	}
	return nil
}

func isRawIPAddress(config addrconfig.Address) bool {
	if config.Facts.Kind == addrconfig.AddressKindRawIP || config.Network.Kind == addrconfig.AddressKindRawIP {
		return true
	}
	if reg, ok := AddressRegistrationForType(config.Type); ok {
		return reg.Kind == addrconfig.AddressKindRawIP
	}
	return false
}

func preparedRawIPProtocolNumber(config addrconfig.Address) (int, bool) {
	if !config.Network.SocketProtocol.Set {
		return 0, false
	}
	return config.Network.SocketProtocol.Value, true
}

// RejectUnsupportedRemainingIPv4 fails fast for get-only ip-mtu /
// ip-pktoptions and for ip-router-alert combinations that are not
// implemented (IPv6, non-raw addresses, IPPROTO_RAW). Linux IP_MTU and
// IP_PKTOPTIONS are get-only; they are not advertised as setters.
func RejectUnsupportedRemainingIPv4(config addrconfig.Address) error {
	for _, action := range config.Network.Actions {
		switch action.Kind {
		case addrconfig.SocketActionGetOnly:
			spelling, kernel := getOnlyNames(action)
			typ := config.Type
			if typ == "" {
				return fmt.Errorf("%s: %s is get-only; not implemented as a setter", spelling, kernel)
			}
			return fmt.Errorf("%s: option %q is get-only; %s is not implemented as a setter", typ, spelling, kernel)
		case addrconfig.SocketActionRouterAlert:
			if err := rejectPreparedRouterAlert(config, action); err != nil {
				return err
			}
		}
	}
	return nil
}
