//go:build linux

package xio

import "golang.org/x/sys/unix"

// golang.org/x/sys/unix exports IPPROTO_SCTP (same value as SOL_SCTP) but
// not SCTP_NODELAY / SCTP_MAXSEG.
const (
	solSCTP     = unix.IPPROTO_SCTP // SOL_SCTP == 132
	sctpNodelay = 3                 // SCTP_NODELAY
	sctpMaxseg  = 13                // SCTP_MAXSEG
)

// lookupNamedPastSocketInt maps a named option to level/opt after socket().
// Bare flag → 1; with '=' → integer, including 0.
func lookupNamedPastSocketInt(name string) (level, opt int, ok bool, err error) {
	switch name {
	case "so-debug":
		return solSocket, soDebug, true, nil
	case "so-dontroute":
		return solSocket, soDontroute, true, nil
	case "so-oobinline":
		return solSocket, soOobinline, true, nil
	case "so-rcvlowat":
		return solSocket, unix.SO_RCVLOWAT, true, nil
	case "so-sndlowat":
		// Linux exposes SO_SNDLOWAT but rejects setsockopt with ENOPROTOOPT.
		// Reject before the syscall so this never appears to be a silent no-op.
		return 0, 0, true, errNamedOptUnsupported
	case "so-priority":
		return solSocket, unix.SO_PRIORITY, true, nil
	case "so-passcred":
		return solSocket, unix.SO_PASSCRED, true, nil
	case "so-no-check":
		return solSocket, unix.SO_NO_CHECK, true, nil
	case "so-detach-filter":
		// The kernel ignores optval; this removes a filter attached
		// externally (inherited fd). SO_ATTACH_FILTER is unsupported.
		return solSocket, unix.SO_DETACH_FILTER, true, nil
	case "tcp-cork":
		return unix.IPPROTO_TCP, unix.TCP_CORK, true, nil
	case "tcp-defer-accept":
		return unix.IPPROTO_TCP, unix.TCP_DEFER_ACCEPT, true, nil
	case "tcp-linger2":
		return unix.IPPROTO_TCP, unix.TCP_LINGER2, true, nil
	case "tcp-maxseg":
		return unix.IPPROTO_TCP, unix.TCP_MAXSEG, true, nil
	case "tcp-quickack":
		return unix.IPPROTO_TCP, unix.TCP_QUICKACK, true, nil
	case "tcp-syncnt":
		return unix.IPPROTO_TCP, unix.TCP_SYNCNT, true, nil
	case "tcp-window-clamp":
		return unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP, true, nil
	case "nopush", "noopt", "tcp-nopush", "tcp-noopt":
		return 0, 0, true, errNamedOptUnsupported
	case "sctp-nodelay":
		return solSCTP, sctpNodelay, true, nil
	case "sctp-maxseg":
		return solSCTP, sctpMaxseg, true, nil
	default:
		return 0, 0, false, nil
	}
}

func lookupNamedConnectedInt(name string) (level, opt int, ok bool, err error) {
	if name == "tcp-maxseg-late" {
		return unix.IPPROTO_TCP, unix.TCP_MAXSEG, true, nil
	}
	return 0, 0, false, nil
}
