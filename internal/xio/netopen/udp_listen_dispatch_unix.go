//go:build linux || darwin

package netopen

import "net"

func newUDPListenForkListener(base *udpForkListener) net.Listener {
	return base
}
