//go:build darwin

package xio

import (
	"github.com/oittaa/socat/internal/addrconfig"
	"golang.org/x/sys/unix"
)

func lookupNamedPastSocketInt(id addrconfig.NamedSocket) (level, opt int, ok bool, err error) {
	switch id {
	case addrconfig.NamedSocketDebug:
		return solSocket, soDebug, true, nil
	case addrconfig.NamedSocketDontRoute:
		return solSocket, soDontroute, true, nil
	case addrconfig.NamedSocketOOBInline:
		return solSocket, soOobinline, true, nil
	case addrconfig.NamedSocketRcvLowat:
		return solSocket, unix.SO_RCVLOWAT, true, nil
	case addrconfig.NamedSocketSndLowat:
		return solSocket, unix.SO_SNDLOWAT, true, nil
	case addrconfig.NamedSocketTCPMaxSeg:
		return unix.IPPROTO_TCP, unix.TCP_MAXSEG, true, nil
	case addrconfig.NamedSocketNoPush:
		return unix.IPPROTO_TCP, unix.TCP_NOPUSH, true, nil
	case addrconfig.NamedSocketNoOpt:
		return unix.IPPROTO_TCP, unix.TCP_NOOPT, true, nil
	case addrconfig.NamedSocketNone:
		return 0, 0, false, nil
	default:
		return 0, 0, true, errNamedOptUnsupported
	}
}

func lookupNamedConnectedInt(id addrconfig.NamedSocket) (level, opt int, ok bool, err error) {
	if id == addrconfig.NamedSocketTCPMaxSegLate {
		return unix.IPPROTO_TCP, unix.TCP_MAXSEG, true, nil
	}
	return 0, 0, false, nil
}
