//go:build windows

package xio

func lookupNamedPastSocketInt(name string) (level, opt int, ok bool, err error) {
	switch name {
	case "so-debug":
		return solSocket, soDebug, true, nil
	case "so-dontroute":
		return solSocket, soDontroute, true, nil
	case "so-oobinline":
		return solSocket, soOobinline, true, nil
	case "tcp-cork", "tcp-defer-accept", "tcp-linger2", "tcp-maxseg",
		"tcp-quickack", "tcp-syncnt", "tcp-window-clamp":
		return 0, 0, true, errNamedOptUnsupported
	default:
		return 0, 0, false, nil
	}
}

func lookupNamedConnectedInt(name string) (level, opt int, ok bool, err error) {
	if name == "tcp-maxseg-late" {
		return 0, 0, true, errNamedOptUnsupported
	}
	return 0, 0, false, nil
}
