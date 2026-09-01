//go:build windows

package netopen

import (
	"net"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func udpForkUsesPacketDispatch(parse.Spec) bool { return true }

func udpForkSharesListenSocket() bool { return true }

func udpForkUsesPeekDial() bool { return false }

func readUDPForkOpener(pc *net.UDPConn, p []byte, wantCtrl bool, oobBuffer []byte, _ bool) (int, []byte, *net.UDPAddr, error) {
	return xio.ReadUDPMsgWithBuffer(pc, p, wantCtrl, oobBuffer)
}

func readQueuedUDPForkPacket(_ *net.UDPConn, _ []byte, _ bool, _ []byte) (int, []byte, *net.UDPAddr, bool, error) {
	return 0, nil, nil, false, nil
}
