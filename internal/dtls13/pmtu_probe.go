package dtls13

import (
	"crypto/hmac"
	"crypto/rand"
	"time"
)

type mtuProbe struct {
	cookie     [rrcCookieLen]byte
	size       int
	generation uint64
	deadline   time.Time
	path       packetPath
}

type mtuDiscovery struct {
	generation    uint64
	outstanding   *mtuProbe
	lastAckedSize int
	lastFailed    bool
}

func (s *session) resetMTUProbes() {
	s.mtu.generation++
	s.mtu.outstanding = nil
	s.mtu.lastAckedSize = 0
	s.mtu.lastFailed = false
}

func (s *session) probeCID() []byte {
	if s.handshake.cidNegotiated {
		return s.handshake.peerCID
	}
	return nil
}

func (s *session) canSendMTUProbe() error {
	if !s.canProbe {
		return errProbeDisabled
	}
	if s.handshake == nil || !s.handshake.complete || !s.handshake.rrc || !s.handshake.cidNegotiated {
		return errProbeDisabled
	}
	if s.path == nil {
		return errProbeDisabled
	}
	if s.path.probe != nil || s.updatePending || s.updating {
		return errProbeBusy
	}
	if s.mtu.outstanding != nil {
		return errProbePending
	}
	return nil
}

func (s *session) startMTUProbe(datagramSize int, now time.Time) error {
	if err := s.canSendMTUProbe(); err != nil {
		return err
	}
	cid := s.probeCID()
	tag := s.recordTagLen()
	if datagramSize > s.mtuCeiling() {
		return errProbeSize
	}
	pad, err := rrcProbePadding(datagramSize, len(cid), tag)
	if err != nil {
		return err
	}
	var cookie [rrcCookieLen]byte
	if _, err := rand.Read(cookie[:]); err != nil {
		return err
	}
	body := append([]byte{pathChallenge}, cookie[:]...)
	probe := &mtuProbe{
		cookie:     cookie,
		size:       datagramSize,
		generation: s.mtu.generation,
		deadline:   now.Add(probeTimeout),
		path:       s.path.peer,
	}
	s.mtu.outstanding = probe
	s.mtu.lastFailed = false
	s.mtu.lastAckedSize = 0
	_, err = s.sendRecordLimited(s.currentWriteEpoch(), contentRRC, body, cid, pad, s.mtuCeiling(), func(packet []byte) error {
		if len(packet) != datagramSize {
			return errProbeSize
		}
		return s.send(packet)
	})
	if err != nil {
		s.mtu.outstanding = nil
		if isMessageTooLong(err) {
			s.mtu.lastFailed = true
			return errProbeTooBig
		}
		return err
	}
	return nil
}

func (s *session) receiveMTUProbe(from packetPath, body []byte, now time.Time) {
	probe := s.mtu.outstanding
	if probe == nil || len(body) != rrcMessageLen {
		return
	}
	if s.path != nil && s.path.probe != nil || s.updatePending || s.updating {
		return
	}
	if body[0] != pathResponse && body[0] != pathDrop {
		return
	}
	if probe.generation != s.mtu.generation {
		return
	}
	if !hmac.Equal(body[1:], probe.cookie[:]) {
		return
	}
	if from != probe.path {
		return
	}
	if !now.Before(probe.deadline) {
		return
	}
	s.mtu.outstanding = nil
	if body[0] == pathDrop {
		s.mtu.lastFailed = true
		return
	}
	s.mtu.lastAckedSize = probe.size
}

func (s *session) tickMTUProbe(now time.Time) {
	probe := s.mtu.outstanding
	if probe == nil || now.Before(probe.deadline) {
		return
	}
	s.mtu.outstanding = nil
	s.mtu.lastFailed = true
}
