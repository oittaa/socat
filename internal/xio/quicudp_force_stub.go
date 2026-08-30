//go:build darwin || windows

package xio

import "net"

func forceQUICUDPBuffers(net.PacketConn, int) {}
