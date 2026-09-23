package sockopt

import (
	"fmt"
	"net"
	"syscall"

	"github.com/oittaa/socat/internal/addrconfig"
)

// ApplyConnFDLifecycle applies descriptor lifecycle on a connected socket.
// The xio core registers the implementation.
var ApplyConnFDLifecycle func(c syscall.Conn, s addrconfig.Address) error

func applyConnFDLifecycle(c syscall.Conn, s addrconfig.Address) error {
	if ApplyConnFDLifecycle == nil {
		return fmt.Errorf("fd lifecycle is not registered")
	}
	return ApplyConnFDLifecycle(c, s)
}

// DrainRecvErr drains MSG_ERRQUEUE after an I/O error. The xio core registers it.
var DrainRecvErr func(err error, enabled bool, c syscall.Conn, g Session)

const AncillaryBufferSize = 1024

// Session receives ancillary logs and per-session output variables.
type Session interface {
	Infof(string, ...any)
	Noticef(string, ...any)
	SetSessionVar(string, string)
}

// WrapUDPAncillary returns c unchanged unless recv ancillary options or
// ip-recverr are enabled. Recv ancillary uses ReadMsgUDP so cmsgs are
// observed. ip-recverr drains MSG_ERRQUEUE on I/O errors for diagnostics
// and never treats error-queue payload as received data.
func WrapUDPAncillary(c *net.UDPConn, s addrconfig.Address, g Session) net.Conn {
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
	g        Session
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
		if DrainRecvErr != nil {
			DrainRecvErr(err, true, c.UDPConn, c.g)
		}
	}
	return n, err
}

func (c *udpAncillaryConn) Write(p []byte) (int, error) {
	n, err := c.UDPConn.Write(p)
	if err != nil && c.recvErr {
		if DrainRecvErr != nil {
			DrainRecvErr(err, true, c.UDPConn, c.g)
		}
	}
	return n, err
}
