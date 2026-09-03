package xio

import (
	"net"

	"github.com/oittaa/socat/internal/parse"
)

const AncillaryBufferSize = 1024

// WrapUDPAncillary returns c unchanged unless recv ancillary options or
// ip-recverr are enabled. Recv ancillary uses ReadMsgUDP so cmsgs are
// observed. ip-recverr drains MSG_ERRQUEUE on I/O errors for diagnostics
// and never treats error-queue payload as received data.
func WrapUDPAncillary(c *net.UDPConn, s parse.Spec, g *Global) net.Conn {
	if c == nil {
		return nil
	}
	wantCtrl := NeedAncillary(s)
	recvErr := NeedRecvErr(s)
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
	oob      [AncillaryBufferSize]byte
}

func (c *udpAncillaryConn) Read(p []byte) (int, error) {
	var n int
	var err error
	if c.wantCtrl {
		var oob []byte
		n, oob, _, err = ReadUDPMsgWithBuffer(c.UDPConn, p, true, c.oob[:])
		if err == nil {
			ProcessAncillary(oob, c.g)
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
