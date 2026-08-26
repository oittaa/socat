//go:build windows

package xio

import (
	"errors"
	"fmt"
	"net"

	"github.com/oittaa/socat/internal/parse"
)

func NeedAncillary(parse.Spec) bool { return false }

func ApplyAncillaryRecvOpts(_ int, s parse.Spec) error {
	if !ancillaryRecvRequested(s) {
		return nil
	}
	return fmt.Errorf("recv ancillary options are not supported on this platform")
}

func ApplyIPSendOpts(fd int, s parse.Spec, network string) error {
	return applyIPTTLTOS(fd, s, network)
}

func ProcessAncillary([]byte, *Global) {}

func ReadUDPMsg(c *net.UDPConn, p []byte, _ bool) (int, []byte, *net.UDPAddr, error) {
	n, addr, err := c.ReadFromUDP(p)
	return n, nil, addr, err
}

func ApplyUDPConnOpts(c *net.UDPConn, s parse.Spec, network string) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		optionErr = ApplyAncillaryRecvOpts(int(fd), s)
		if optionErr == nil {
			optionErr = ApplyIPSendOpts(int(fd), s, network)
		}
		if optionErr == nil {
			optionErr = ApplySocketOptions(int(fd), s)
		}
		if optionErr == nil {
			optionErr = ApplyLateSocketOptions(int(fd), s)
		}
	})
	return errors.Join(controlErr, optionErr)
}
