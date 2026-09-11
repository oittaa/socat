//go:build linux

package xio

import (
	"github.com/oittaa/socat/internal/addrconfig"
	"golang.org/x/sys/unix"
)

// golang.org/x/sys/unix exports IPPROTO_SCTP (same value as SOL_SCTP) but
// not SCTP_NODELAY / SCTP_MAXSEG.
const (
	solSCTP     = unix.IPPROTO_SCTP // SOL_SCTP == 132
	sctpNodelay = 3                 // SCTP_NODELAY
	sctpMaxseg  = 13                // SCTP_MAXSEG
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
		// Linux exposes SO_SNDLOWAT but rejects setsockopt with ENOPROTOOPT.
		// Reject before the syscall so this never appears to be a silent no-op.
		return 0, 0, true, errNamedOptUnsupported
	case addrconfig.NamedSocketPriority:
		return solSocket, unix.SO_PRIORITY, true, nil
	case addrconfig.NamedSocketPassCred:
		return solSocket, unix.SO_PASSCRED, true, nil
	case addrconfig.NamedSocketNoCheck:
		return solSocket, unix.SO_NO_CHECK, true, nil
	case addrconfig.NamedSocketDetachFilter:
		// The kernel ignores optval; this removes a filter attached
		// externally (inherited fd). SO_ATTACH_FILTER is unsupported.
		return solSocket, unix.SO_DETACH_FILTER, true, nil
	case addrconfig.NamedSocketTCPCork:
		return unix.IPPROTO_TCP, unix.TCP_CORK, true, nil
	case addrconfig.NamedSocketTCPDeferAccept:
		return unix.IPPROTO_TCP, unix.TCP_DEFER_ACCEPT, true, nil
	case addrconfig.NamedSocketTCPLinger2:
		return unix.IPPROTO_TCP, unix.TCP_LINGER2, true, nil
	case addrconfig.NamedSocketTCPMaxSeg:
		return unix.IPPROTO_TCP, unix.TCP_MAXSEG, true, nil
	case addrconfig.NamedSocketTCPQuickAck:
		return unix.IPPROTO_TCP, unix.TCP_QUICKACK, true, nil
	case addrconfig.NamedSocketTCPSyncnt:
		return unix.IPPROTO_TCP, unix.TCP_SYNCNT, true, nil
	case addrconfig.NamedSocketTCPWindowClamp:
		return unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP, true, nil
	case addrconfig.NamedSocketNoPush, addrconfig.NamedSocketNoOpt:
		return 0, 0, true, errNamedOptUnsupported
	case addrconfig.NamedSocketSCTPNodelay:
		return solSCTP, sctpNodelay, true, nil
	case addrconfig.NamedSocketSCTPMaxSeg:
		return solSCTP, sctpMaxseg, true, nil
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
