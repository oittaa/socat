//go:build windows

package xio

import (
	"errors"
	"net"

	"github.com/oittaa/socat/internal/parse"
)

func NeedAncillary(parse.Spec) bool { return false }

func ApplyAncillaryRecvOpts(int, parse.Spec) error { return nil }

func ApplyIPSendOpts(int, parse.Spec, string) error { return nil }

func ProcessAncillary([]byte, *Global) {}

func ReadUDPMsg(c *net.UDPConn, p []byte, _ bool) (int, []byte, *net.UDPAddr, error) {
	n, addr, err := c.ReadFromUDP(p)
	return n, nil, addr, err
}

func ApplyUDPConnOpts(c *net.UDPConn, s parse.Spec, _ string) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		optionErr = ApplySocketTimeos(int(fd), s)
	})
	return errors.Join(controlErr, optionErr)
}
