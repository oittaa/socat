package addrconfig

import (
	"fmt"
	"strings"
)

func decodeVSOCKPositional(n *Network, typ string, params []string) error {
	if n.Role == AddressRoleListen {
		if len(params) == 1 && params[0] != "" {
			port, err := vsockUint32(params[0])
			if err != nil {
				return fmt.Errorf("%s: port: %w", typ, err)
			}
			n.VSOCKListen, n.VSOCKListenSet = port, true
		}
		return nil
	}
	if len(params) == 2 {
		cid, err := vsockUint32(params[0])
		if err != nil {
			return fmt.Errorf("%s: cid: %w", typ, err)
		}
		if params[0] == "" {
			cid = ^uint32(0)
		}
		port, err := vsockUint32(params[1])
		if err != nil {
			return fmt.Errorf("%s: port: %w", typ, err)
		}
		n.VSOCKConnect, n.VSOCKConnectSet = VSOCKEndpoint{CID: cid, Port: port}, true
	}
	return nil
}

func vsockUint32(value string) (uint32, error) {
	if strings.TrimSpace(value) == "" {
		return 0, nil
	}
	n, err := ParseSizeT(value)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil // #nosec G115 -- VSOCK uses the C uint32_t conversion
}

func decodeVSOCKBind(value string) (VSOCKEndpoint, bool, error) {
	cidStr, portStr, hasPort := splitVSOCKBind(value)
	cid := ^uint32(0)
	if cidStr != "" {
		var err error
		cid, err = vsockUint32(cidStr)
		if err != nil {
			return VSOCKEndpoint{}, hasPort, fmt.Errorf("bind: cid: %w", err)
		}
	}
	ep := VSOCKEndpoint{CID: cid, Port: ^uint32(0)}
	if !hasPort {
		return ep, false, nil
	}
	port, err := vsockUint32(portStr)
	if err != nil {
		return VSOCKEndpoint{}, true, fmt.Errorf("bind: port: %w", err)
	}
	ep.Port = port
	return ep, true, nil
}

func splitVSOCKBind(bind string) (cidStr, portStr string, hasPort bool) {
	if i := strings.IndexByte(bind, ':'); i >= 0 {
		return bind[:i], bind[i+1:], true
	}
	return bind, "", false
}
