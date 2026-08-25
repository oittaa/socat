//go:build !windows

package netopen

import "net"

func newUDPListenForkListener(base *udpForkListener) net.Listener {
	return base
}
