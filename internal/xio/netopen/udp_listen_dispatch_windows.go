//go:build windows

package netopen

import (
	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/logx"
	"net"

	"github.com/oittaa/socat/internal/xio"
)

func udpForkUsesPacketDispatch(addrconfig.Address) bool { return true }

func udpForkSharesListenSocket() bool { return true }

func udpForkUsesPeekDial() bool { return false }

func readUDPForkOpener(pc *net.UDPConn, p []byte, wantCtrl bool, oobBuffer []byte, _ bool, _ *logx.Logger) (int, []byte, *net.UDPAddr, error) {
	return xio.ReadUDPMsgWithBuffer(pc, p, wantCtrl, oobBuffer)
}

func readQueuedUDPForkPacket(_ *net.UDPConn, _ []byte, _ bool, _ []byte, _ *logx.Logger) (int, []byte, *net.UDPAddr, bool, error) {
	return 0, nil, nil, false, nil
}
