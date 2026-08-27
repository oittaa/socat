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

func ProcessAncillary([]byte, *Global) {}

func ReadUDPMsg(c *net.UDPConn, p []byte, _ bool) (int, []byte, *net.UDPAddr, error) {
	n, addr, err := c.ReadFromUDP(p)
	return n, nil, addr, err
}

func applyOneIPRecvOpt(_ int, e IPAncillaryEntry, _ parse.Option, family ipFamily) error {
	return rejectIPAncillaryApply(e.Canonical, family)
}

func ApplyUDPConnOpts(c *net.UDPConn, s parse.Spec, network string) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		// Send and recv IP/ancillary options are PH_PASTSOCKET
		// (DialControl / ListenControl → ApplyPastSocketPhase).
		optionErr = ApplySocketOptions(int(fd), s)
		if optionErr == nil {
			optionErr = ApplyLateSocketOptions(int(fd), s)
		}
	})
	return errors.Join(controlErr, optionErr)
}
