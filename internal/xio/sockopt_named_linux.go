//go:build linux

package xio

import "golang.org/x/sys/unix"

// lookupNamedPastSocketInt is classic xio-socket.c opt_so_debug /
// opt_so_dontroute / opt_so_oobinline and xio-tcp.c TCP_* PH_PASTSOCKET
// records (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba;
// official master af5388c898c7bb60997935aee93c223deba60c4a is the same).
func lookupNamedPastSocketInt(name string) (level, opt int, ok bool, err error) {
	switch name {
	case "so-debug":
		return solSocket, soDebug, true, nil
	case "so-dontroute":
		return solSocket, soDontroute, true, nil
	case "so-oobinline":
		return solSocket, soOobinline, true, nil
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
