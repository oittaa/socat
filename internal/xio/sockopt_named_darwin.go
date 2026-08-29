//go:build darwin

package xio

import "golang.org/x/sys/unix"

// lookupNamedPastSocketInt maps a named option to level/opt after socket().
// Darwin supports TCP_MAXSEG, TCP_NOPUSH, and TCP_NOOPT. Linux-only TCP_*
// names fail instead of becoming no-ops.
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
		return solSocket, unix.SO_SNDLOWAT, true, nil
	case "tcp-maxseg":
		return unix.IPPROTO_TCP, unix.TCP_MAXSEG, true, nil
	case "nopush", "tcp-nopush":
		return unix.IPPROTO_TCP, unix.TCP_NOPUSH, true, nil
	case "noopt", "tcp-noopt":
		return unix.IPPROTO_TCP, unix.TCP_NOOPT, true, nil
	case "tcp-cork", "tcp-defer-accept", "tcp-linger2", "tcp-quickack", "tcp-syncnt", "tcp-window-clamp",
		"sctp-nodelay", "sctp-maxseg",
		"so-priority", "so-passcred", "so-no-check", "so-detach-filter":
		return 0, 0, true, errNamedOptUnsupported
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
