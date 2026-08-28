//go:build unix && !linux && !darwin

package xio

import "golang.org/x/sys/unix"

// Darwin/BSD advertise TCP_MAXSEG; Linux-only TCP_* names fail instead of
// becoming no-ops (classic xio-tcp.c #ifdef TCP_CORK and friends).
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
	case "nopush", "noopt", "tcp-nopush", "tcp-noopt",
		"tcp-cork", "tcp-defer-accept", "tcp-linger2", "tcp-quickack", "tcp-syncnt", "tcp-window-clamp",
		"sctp-nodelay", "sctp-maxseg",
		"so-priority", "so-passcred", "so-no-check":
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
