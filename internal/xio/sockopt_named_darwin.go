//go:build darwin

package xio

import "golang.org/x/sys/unix"

// Darwin TCP_MAXSEG plus TCP_NOPUSH / TCP_NOOPT (classic xio-tcp.c
// #ifdef TCP_NOPUSH / TCP_NOOPT, tag-1.8.1.3 12c08bf; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same). Linux-only TCP_*
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
