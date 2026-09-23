//go:build windows

package sockopt

import (
	"errors"
	"net"

	"github.com/oittaa/socat/internal/addrconfig"
)

func NeedAncillary(addrconfig.Address) bool { return false }

func ProcessAncillary([]byte, Session) {}

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

func applyPreparedIPRecv(_ int, e ipAncillaryEntry, _ int, family IPFamily) error {
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
	return errors.Join(controlErr, optionErr)
}
