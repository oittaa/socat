package dtls13

import (
	"errors"
	"math"
	"time"
)

var errUpdatePending = errors.New("dtls: waiting for key update acknowledgement")

var postTypes = [...]byte{msgNewConnectionID, msgRequestConnectionID, msgKeyUpdate}

func (s *session) startPost(typ byte, body []byte, now time.Time) error {
	if !s.handshake.complete || s.updating || s.outbound != nil && !s.outbound.complete {
		return errUpdatePending
	}
	if f := s.post[typ]; f != nil && !f.complete {
		return errUpdatePending
	}
	m, err := s.handshake.message(typ, s.currentWriteEpoch(), body)
	if err != nil {
		return err
	}
	f, err := newFlight([]handshakeMessage{m}, initialRetransmit)
	if err != nil {
		return err
	}
	s.post[typ] = f
	return s.transmit(f, now)
}

func (s *session) requestKeyUpdate(requestPeer bool, now time.Time) error {
	if !s.handshake.complete || s.closed {
		return errUnexpectedMessage
	}
	if s.currentWriteEpoch() >= 1<<48-1 {
		return errSequence
	}
	s.updatePending = true
	s.requestPeerUpdate = s.requestPeerUpdate || requestPeer
	return s.advancePost(now)
}

func (s *session) advancePost(now time.Time) error {
	if !s.handshake.complete || s.outbound != nil && !s.outbound.complete {
		return nil
	}
	if h := s.handshake; h.schedule != nil {
		clear(h.schedule.master)
		clear(h.schedule.clientHandshake)
		clear(h.schedule.serverHandshake)
		clear(h.clientApplication)
		clear(h.serverApplication)
		h.schedule, h.clientApplication, h.serverApplication = nil, nil, nil
		s.handleHandshake = nil
	}
	if old := s.write[2]; old != nil {
		clear(old.secret)
	}
	delete(s.write, 0)
	delete(s.write, 2)
	if s.updating {
		for _, f := range s.post {
			if !f.complete {
				return nil
			}
		}
		epoch := s.currentWriteEpoch()
		secret, keys, err := s.updatedKeys(s.write[epoch].secret)
		if err != nil {
			return err
		}
		s.write[epoch+1] = &writeEpoch{keys: keys, secret: secret}
		clear(s.write[epoch].secret)
		delete(s.write, epoch)
		s.updating = false
	}
	for typ, f := range s.post {
		if f.complete {
			delete(s.post, typ)
		}
	}
	if s.updatePending {
		if s.currentWriteEpoch() >= 1<<48-1 {
			return errSequence
		}
		request := byte(0)
		if s.requestPeerUpdate {
			request = 1
		}
		if err := s.startPost(msgKeyUpdate, []byte{request}, now); err != nil {
			return err
		}
		s.updating, s.updatePending, s.requestPeerUpdate = true, false, false
	}
	if !s.updating && s.cidResponse != nil && s.post[msgNewConnectionID] == nil && len(s.immediateCIDs) == 0 {
		count := *s.cidResponse
		s.cidResponse = nil
		return s.provideCIDs(int(count), false, now)
	}
	if !s.updating && s.wantCIDs && !s.cidRequested && s.post[msgRequestConnectionID] == nil {
		s.wantCIDs = false
		if s.handshake.cidNegotiated && len(s.handshake.peerCID) != 0 {
			return s.requestCIDs(4, now)
		}
	}
	return nil
}

func (s *session) updatedKeys(secret []byte) ([]byte, *trafficKeys, error) {
	updated, err := nextTrafficSecret(s.handshake.state.CipherSuite, secret)
	if err != nil {
		return nil, nil, err
	}
	keys, err := newTrafficKeys(s.handshake.state.CipherSuite, updated)
	return updated, keys, err
}

func (s *session) acknowledgePost(records []recordNumber, authenticated bool, now time.Time) error {
	for _, typ := range postTypes {
		if f := s.post[typ]; f != nil {
			progress := f.acknowledge(records, authenticated)
			if progress && !f.complete {
				if err := s.transmit(f, now); err != nil {
					return err
				}
			}
		}
	}
	return s.advancePost(now)
}

func (s *session) receivePost(m handshakeMessage, now time.Time) error {
	if m.epoch < 3 || m.epoch != s.readApplicationEpoch {
		return errUnexpectedMessage
	}
	switch m.typ {
	case msgKeyUpdate:
		if len(m.body) != 1 {
			return errDecode
		}
		if m.body[0] > 1 || m.epoch != s.readApplicationEpoch {
			return errIllegalParameter
		}
		if m.epoch == math.MaxUint64 {
			return errSequence
		}
		secret, keys, err := s.updatedKeys(s.read[m.epoch].secret)
		if err != nil {
			return err
		}
		s.readApplicationEpoch = m.epoch + 1
		s.read[m.epoch+1] = &readEpoch{keys: keys, secret: secret}
		// An acknowledged client Finished precedes every client KeyUpdate.
		if old := s.read[2]; old != nil {
			clear(old.secret)
			delete(s.read, 2)
		}
		if m.body[0] == 1 && s.currentWriteEpoch() < 1<<48-1 {
			s.updatePending = true
		}
		return s.sendACK()
	case msgNewSessionTicket:
		if !s.handshake.client {
			return errUnexpectedMessage
		}
		// Tickets are acknowledged but not retained; resumption is disabled.
		if err := validateSessionTicket(m.body); err != nil {
			return err
		}
		return s.sendACK()
	case msgNewConnectionID:
		return s.receiveCIDs(m.body)
	case msgRequestConnectionID:
		if !s.handshake.cidNegotiated || len(s.handshake.localCID) == 0 {
			return errUnexpectedMessage
		}
		if len(m.body) != 1 {
			return errDecode
		}
		if s.cidResponse != nil {
			return alertError(52)
		}
		count := m.body[0]
		s.cidResponse = &count
		return s.sendACK()
	default:
		return errUnexpectedMessage
	}
}

func validateSessionTicket(body []byte) error {
	r := wireReader{data: body}
	r.take(8)
	r.vector8()
	ticket := r.vector16()
	ext := r.vector16()
	if r.done() != nil || len(ticket) == 0 {
		return errDecode
	}
	_, err := parseExtensions(ext, msgNewSessionTicket)
	return err
}
