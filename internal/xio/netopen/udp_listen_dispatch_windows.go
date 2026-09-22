//go:build windows

package netopen

import (
	"net"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"
)

func udpForkUsesPacketDispatch(addrconfig.Address) bool { return true }

func udpForkSharesListenSocket() bool { return true }

func udpForkUsesPeekDial() bool { return false }

func readUDPForkOpener(pc *net.UDPConn, p []byte, wantCtrl bool, oobBuffer []byte, _ bool) (int, []byte, *udpPeer, error) {
	n, oob, addr, err := xio.ReadUDPMsgWithBuffer(pc, p, wantCtrl, oobBuffer)
	return n, oob, udpPeerFromNet(addr), err
}

func readQueuedUDPForkPacket(_ *net.UDPConn, _ []byte, _ bool, _ []byte) (int, []byte, *udpPeer, bool, error) {
	return 0, nil, nil, false, nil
}
