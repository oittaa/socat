//go:build windows

package xio

import (
	"errors"
	"fmt"
	"github.com/oittaa/socat/internal/addrconfig"
	"net"
)

func NeedAncillary(addrconfig.Address) bool { return false }

func ApplyAncillaryRecvOpts(_ int, s addrconfig.Address) error {
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

func ReadUDPMsgWithBuffer(c *net.UDPConn, p []byte, _ bool, _ []byte) (int, []byte, *net.UDPAddr, error) {
	n, addr, err := c.ReadFromUDP(p)
	return n, nil, addr, err
}

// ControlMessageBytes returns oob[:oobn]. Windows recv paths do not enable
// ReadMsg control-message delivery.
func ControlMessageBytes(oob []byte, oobn, _ int) []byte {
	if oobn <= 0 {
		return nil
	}
	if oobn > len(oob) {
		oobn = len(oob)
	}
	return oob[:oobn]
}

func applyPreparedIPRecv(_ int, e IPAncillaryEntry, _ int, family ipFamily) error {
	return rejectIPAncillaryApply(e, family)
}

func ApplyUDPConnOpts(c *net.UDPConn, s addrconfig.Address, _ string) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		// Send and recv IP/ancillary options apply after socket()
		// (DialControl / ListenControl → ApplyPastSocketPhase).
		optionErr = ApplyLateSocketOptions(int(fd), s)
		if optionErr == nil {
			optionErr = ApplyGenericSetsockopt(int(fd), s, SockoptPhaseConnected)
		}
	})
	if err := errors.Join(controlErr, optionErr); err != nil {
		return err
	}
	return ApplyFDLifecycleToConn(c, s)
}
