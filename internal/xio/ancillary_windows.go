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

func applyOneIPRecvOpt(_ int, e IPAncillaryEntry, _ parse.Option, family ipFamily) error {
	return rejectIPAncillaryApply(e.Canonical, family)
}

func ApplyUDPConnOpts(c *net.UDPConn, s parse.Spec, _ string) error {
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
