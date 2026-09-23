package xio

import (
	"net"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio/sockopt"
)

// WrapUDPAncillary returns c unchanged unless recv ancillary options or
// ip-recverr are enabled. Recv ancillary uses ReadMsgUDP so cmsgs are
// observed. ip-recverr drains MSG_ERRQUEUE on I/O errors for diagnostics
// and never treats error-queue payload as received data.
func WrapUDPAncillary(c *net.UDPConn, s addrconfig.Address, g *Global) net.Conn {
	if c == nil {
		return nil
	}
	wantCtrl := sockopt.NeedAncillary(s)
	recvErr := sockopt.NeedRecvErr(s)
	if !wantCtrl && !recvErr {
		return c
	}
	return &udpAncillaryConn{UDPConn: c, g: g, wantCtrl: wantCtrl, recvErr: recvErr}
}

type udpAncillaryConn struct {
	*net.UDPConn
	g        *Global
	wantCtrl bool
	recvErr  bool
	oob      [sockopt.AncillaryBufferSize]byte
}

func (c *udpAncillaryConn) Read(p []byte) (int, error) {
	var n int
	var err error
	if c.wantCtrl {
		var oob []byte
		n, oob, _, err = sockopt.ReadUDPMsgWithBuffer(c.UDPConn, p, true, c.oob[:])
		if err == nil {
			sockopt.ProcessAncillary(oob, c.g)
		}
	} else {
		n, err = c.UDPConn.Read(p)
	}
	if err != nil && c.recvErr {
		DrainRecvErrOnError(err, true, c.UDPConn, c.g)
	}
	return n, err
}

func (c *udpAncillaryConn) Write(p []byte) (int, error) {
	n, err := c.UDPConn.Write(p)
	if err != nil && c.recvErr {
		DrainRecvErrOnError(err, true, c.UDPConn, c.g)
	}
	return n, err
}
