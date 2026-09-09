package dtls13

import (
	"errors"
	"math"
	"time"
)

var errOperationPending = errors.New("dtls: handshake, key update, or CID operation pending")

var postTypes = [...]byte{msgNewConnectionID, msgRequestConnectionID, msgKeyUpdate}

// RFC 9147 section 5.8.1 requires final-flight ACK recovery for twice MSL.
const handshakeReadRetention = 4 * time.Minute

func (s *session) discardHandshakeRead() {
	if old := s.epochs.read[2]; old != nil {
		clear(old.secret)
		delete(s.epochs.read, 2)
	}
	s.handshakeReadExpiry = time.Time{}
}

func (s *session) expireHandshakeRead(now time.Time) {
	if !s.handshakeReadExpiry.IsZero() && !now.Before(s.handshakeReadExpiry) {
		s.discardHandshakeRead()
	}
}

func (s *session) startPost(typ byte, body []byte, now time.Time) error {
	if !s.handshake.complete || s.keyUpdate.updating || s.outbound != nil && !s.outbound.complete {
		return errOperationPending
	}
	if f := s.post[typ]; f != nil && !f.complete {
		return errOperationPending
	}
	m, err := s.handshake.message(typ, s.currentWriteEpoch(), body)
	if err != nil {
		return err
	}
	f, err := newFlight([]handshakeMessage{m}, s.retransmitTimer())
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
	s.keyUpdate.localPending = true
	// RFC 9846 §4.7.3: do not queue another update_requested while one is outstanding.
	if requestPeer && !s.keyUpdate.awaitingPeer {
		s.keyUpdate.requestPeer = true
	}
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
	if old := s.epochs.write[2]; old != nil {
		clear(old.secret)
	}
	delete(s.epochs.write, 0)
	delete(s.epochs.write, 2)
	if s.epochs.read[2] != nil {
		if s.handshake.client {
			s.discardHandshakeRead()
		} else if s.handshakeReadExpiry.IsZero() {
			s.handshakeReadExpiry = now.Add(handshakeReadRetention)
		}
	}
	if s.keyUpdate.updating {
		for _, f := range s.post {
			if !f.complete {
				return nil
			}
		}
		epoch := s.currentWriteEpoch()
		secret, keys, err := s.updatedKeys(s.epochs.write[epoch].secret)
		if err != nil {
			return err
		}
		s.epochs.write[epoch+1] = &writeEpoch{keys: keys, secret: secret}
		clear(s.epochs.write[epoch].secret)
		delete(s.epochs.write, epoch)
		s.keyUpdate.updating = false
	}
	for typ, f := range s.post {
		if f.complete {
			delete(s.post, typ)
		}
	}
	if s.keyUpdate.localPending {
		if s.currentWriteEpoch() >= 1<<48-1 {
			return errSequence
		}
		request := byte(0)
		if s.keyUpdate.requestPeer && !s.keyUpdate.awaitingPeer {
			request = 1
		}
		if err := s.startPost(msgKeyUpdate, []byte{request}, now); err != nil {
			return err
		}
		s.keyUpdate.updating, s.keyUpdate.localPending, s.keyUpdate.requestPeer = true, false, false
		if request == 1 {
			s.keyUpdate.awaitingPeer = true
		}
	}
	if err := s.respondCIDRequest(now); err != nil {
		return err
	}
	if !s.keyUpdate.updating && s.cid.want && !s.cid.requested && s.post[msgRequestConnectionID] == nil && (s.path == nil || s.path.probe == nil) {
		s.cid.want = false
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
			progress, sample := f.acknowledge(records, authenticated, now)
			s.noteRTT(sample, f)
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
	if m.epoch < 3 || m.epoch != s.epochs.readApplicationEpoch {
		return errUnexpectedMessage
	}
	switch m.typ {
	case msgKeyUpdate:
		if len(m.body) != 1 {
			return errDecode
		}
		if m.body[0] > 1 || m.epoch != s.epochs.readApplicationEpoch {
			return errIllegalParameter
		}
		if m.epoch == math.MaxUint64 {
			return errSequence
		}
		secret, keys, err := s.updatedKeys(s.epochs.read[m.epoch].secret)
		if err != nil {
			return err
		}
		s.epochs.readApplicationEpoch = m.epoch + 1
		s.epochs.read[m.epoch+1] = &readEpoch{keys: keys, secret: secret}
		// An acknowledged client Finished precedes every client KeyUpdate.
		s.discardHandshakeRead()
		s.keyUpdate.awaitingPeer = false
		s.keyUpdate.requestPeer = false
		if m.body[0] == 1 && s.currentWriteEpoch() < 1<<48-1 {
			s.keyUpdate.localPending = true
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
		if s.cid.response != nil {
			return alertError(52)
		}
		count := m.body[0]
		s.cid.response = &count
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
