//go:build windows

package xio

import (
	"net"

	"github.com/oittaa/socat/internal/parse"
)

func NeedAncillary(parse.Spec) bool { return false }

func ApplyAncillaryRecvOpts(int, parse.Spec) {}

func ApplyIPSendOpts(int, parse.Spec, string) {}

func ProcessAncillary([]byte, *Global) {}

func ReadUDPMsg(c *net.UDPConn, p []byte, _ bool) (int, []byte, *net.UDPAddr, error) {
	n, addr, err := c.ReadFromUDP(p)
	return n, nil, addr, err
}

func ApplyUDPConnOpts(*net.UDPConn, parse.Spec, string) {}
