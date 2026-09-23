//go:build windows

package sockopt

import "github.com/oittaa/socat/internal/addrconfig"

func lookupNamedPastSocketInt(id addrconfig.NamedSocket) (level, opt int, ok bool, err error) {
	switch id {
	case addrconfig.NamedSocketDebug:
		return SOLSocket, soDebug, true, nil
	case addrconfig.NamedSocketDontRoute:
		return SOLSocket, soDontroute, true, nil
	case addrconfig.NamedSocketOOBInline:
		return SOLSocket, soOobinline, true, nil
	case addrconfig.NamedSocketNone:
		return 0, 0, false, nil
	default:
		return 0, 0, true, errNamedOptUnsupported
	}
}

func lookupNamedConnectedInt(id addrconfig.NamedSocket) (level, opt int, ok bool, err error) {
	if id == addrconfig.NamedSocketTCPMaxSegLate {
		return 0, 0, true, errNamedOptUnsupported
	}
	return 0, 0, false, nil
}
