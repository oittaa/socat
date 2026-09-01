//go:build linux

package netopen

import "net"

func newUDPListenForkListener(base *udpForkListener) net.Listener { return base }

func udpForkSharesListenSocket() bool { return false }
