//go:build windows

package xio

import "github.com/oittaa/socat/internal/addrconfig"

func lookupNamedPastSocketInt(id addrconfig.NamedSocket) (level, opt int, ok bool, err error) {
	switch id {
	case addrconfig.NamedSocketDebug:
		return solSocket, soDebug, true, nil
	case addrconfig.NamedSocketDontRoute:
		return solSocket, soDontroute, true, nil
	case addrconfig.NamedSocketOOBInline:
		return solSocket, soOobinline, true, nil
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
