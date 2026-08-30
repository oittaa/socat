package xio

import (
	"net"

	"github.com/oittaa/socat/internal/parse"
)

const AncillaryBufferSize = 1024

// WrapUDPAncillary returns c unchanged unless recv ancillary options are
// enabled; then Read uses ReadMsgUDP so cmsgs are observed (UDP-CONNECT and
// any other connected UDP path that would otherwise call Conn.Read).
func WrapUDPAncillary(c *net.UDPConn, s parse.Spec, g *Global) net.Conn {
	if c == nil || !NeedAncillary(s) {
		if c == nil {
			return nil
		}
		return c
	}
	return &udpAncillaryConn{UDPConn: c, g: g}
}

type udpAncillaryConn struct {
	*net.UDPConn
	g   *Global
	oob [AncillaryBufferSize]byte
}

func (c *udpAncillaryConn) Read(p []byte) (int, error) {
	n, oob, _, err := ReadUDPMsgWithBuffer(c.UDPConn, p, true, c.oob[:])
	if err != nil {
		return n, err
	}
	ProcessAncillary(oob, c.g)
	return n, nil
}
