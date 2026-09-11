package xio

import (
	"errors"

	"github.com/oittaa/socat/internal/addrconfig"
)

// Named SOL_SOCKET, TCP, and Linux SCTP integer socket options.
// Bare flag → 1. Kernel rejection fails the call. Linux SO_SNDLOWAT is
// recognized but rejected (kernel ENOPROTOOPT). nopush/noopt work on Darwin;
// Linux and Windows reject. so-bsdcompat, tcp-info, tcp-md5sig, and
// sctp-maxseg-late are not implemented. sctp-nodelay/sctp-maxseg use SOL_SCTP.
var errNamedOptUnsupported = errors.New("not supported on this platform")

func namedSocketOptionName(option addrconfig.NamedSocketOption) string {
	switch option {
	case addrconfig.NamedSocketDebug:
		return "so-debug"
	case addrconfig.NamedSocketDontRoute:
		return "so-dontroute"
	case addrconfig.NamedSocketOOBInline:
		return "so-oobinline"
	case addrconfig.NamedSocketRecvLowWater:
		return "so-rcvlowat"
	case addrconfig.NamedSocketSendLowWater:
		return "so-sndlowat"
	case addrconfig.NamedSocketPriority:
		return "so-priority"
	case addrconfig.NamedSocketPassCred:
		return "so-passcred"
	case addrconfig.NamedSocketNoCheck:
		return "so-no-check"
	case addrconfig.NamedSocketDetachFilter:
		return "so-detach-filter"
	case addrconfig.NamedSocketTCPCork:
		return "tcp-cork"
	case addrconfig.NamedSocketTCPDeferAccept:
		return "tcp-defer-accept"
	case addrconfig.NamedSocketTCPLinger2:
		return "tcp-linger2"
	case addrconfig.NamedSocketTCPMaxSeg:
		return "tcp-maxseg"
	case addrconfig.NamedSocketTCPQuickAck:
		return "tcp-quickack"
	case addrconfig.NamedSocketTCPSyncNT:
		return "tcp-syncnt"
	case addrconfig.NamedSocketTCPWindowClamp:
		return "tcp-window-clamp"
	case addrconfig.NamedSocketTCPNoPush:
		return "nopush"
	case addrconfig.NamedSocketTCPNoOpt:
		return "noopt"
	case addrconfig.NamedSocketSCTPNoDelay:
		return "sctp-nodelay"
	case addrconfig.NamedSocketSCTPMaxSeg:
		return "sctp-maxseg"
	case addrconfig.NamedSocketTCPMaxSegLate:
		return "tcp-maxseg-late"
	case addrconfig.NamedSocketFIOSetown:
		return "fiosetown"
	case addrconfig.NamedSocketSIOCSPGRP:
		return "siocspgrp"
	default:
		return ""
	}
}
