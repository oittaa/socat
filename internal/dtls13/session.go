package dtls13

import (
	"bytes"
	"errors"
	"math"
	"time"
)

type readEpoch struct {
	keys     *trafficKeys
	secret   []byte
	window   replayWindow
	failures uint64
}

type writeEpoch struct {
	keys     *trafficKeys
	secret   []byte
	sequence uint64
}

// ackState is queued ACK record numbers and the RFC 9147 quiet-timer deadline.
type ackState struct {
	pending  []recordNumber
	deadline time.Time
}

// trafficEpochs is installed traffic keys, epoch maps, and secret retention.
type trafficEpochs struct {
	read                 map[uint64]*readEpoch
	write                map[uint64]*writeEpoch
	installed            byte
	readApplicationEpoch uint64
}

// keyUpdateState keeps local KeyUpdate and outstanding peer-update requests
// independent: a local update can be pending while a peer update is outstanding.
type keyUpdateState struct {
	localPending bool
	requestPeer  bool
	awaitingPeer bool
	updating     bool
}

// cidState is CID pools, pending RequestConnectionId, and rotation hooks.
// response is nil when no request is pending; a non-nil pointer (including to
// 0) is a pending reply, including an empty spare list.
type cidState struct {
	local     [][]byte
	immediate [][]byte
	peerSpare [][]byte
	requested bool
	want      bool
	response  *byte
	setLocal  func([][]byte) error
}

// workingMTU is the current path MTU, shrink budget, and last send size.
// Probe search lives in session.mtu (mtuDiscovery); path validation in path.
type workingMTU struct {
	pathMTU      int
	reductions   int
	lastSendSize int
	canProbe     bool
}

// session is driven by one connection event loop. Transport ownership,
// deadlines, and application queues belong to the connection.
type session struct {
	handshake           *handshakeState
	handshakeReceived   time.Time
	handleHandshake     func(handshakeMessage) ([]handshakeMessage, error)
	send                func([]byte) error
	epochs              trafficEpochs
	reassembly          reassembler
	outbound            *flight
	ack                 ackState
	handshakeReadExpiry time.Time
	closed              bool
	post                map[byte]*flight
	keyUpdate           keyUpdateState
	peerClosed          *recordNumber
	cid                 cidState
	path                *pathState
	working             workingMTU
	mtu                 mtuDiscovery
}

func newClientSession(config *Config, send func([]byte) error, now time.Time) (*session, error) {
	h, messages, err := newClientHandshake(config)
	if err != nil {
		return nil, err
	}
	s := newSession(h.handshakeState, h.handle, send)
	if err := s.startFlight(messages, now); err != nil {
		return nil, err
	}
	return s, nil
}

func newSession(h *handshakeState, handle func(handshakeMessage) ([]handshakeMessage, error), send func([]byte) error) *session {
	return &session{
		handshake:       h,
		handleHandshake: handle,
		send:            send,
		epochs: trafficEpochs{
			read:  make(map[uint64]*readEpoch),
			write: map[uint64]*writeEpoch{0: {}},
		},
		post: make(map[byte]*flight),
	}
}

func (s *session) installKeys() error {
	h := s.handshake
	if h.schedule == nil {
		return nil
	}
	for _, pair := range []struct {
		epoch          uint64
		client, server []byte
	}{
		{2, h.schedule.clientHandshake, h.schedule.serverHandshake},
		{3, h.clientApplication, h.serverApplication},
	} {
		if len(pair.client) == 0 || s.epochs.installed&(1<<pair.epoch) != 0 {
			continue
		}
		readSecret, writeSecret := pair.client, pair.server
		if h.client {
			readSecret, writeSecret = pair.server, pair.client
		}
		readKeys, err := newTrafficKeys(h.state.CipherSuite, readSecret)
		if err != nil {
			return err
		}
		writeKeys, err := newTrafficKeys(h.state.CipherSuite, writeSecret)
		if err != nil {
			return err
		}
		s.epochs.read[pair.epoch] = &readEpoch{keys: readKeys, secret: bytes.Clone(readSecret)}
		s.epochs.write[pair.epoch] = &writeEpoch{keys: writeKeys, secret: bytes.Clone(writeSecret)}
		s.epochs.installed |= 1 << pair.epoch
		if pair.epoch == 3 {
			s.epochs.readApplicationEpoch = 3
		}
	}
	return nil
}

func (s *session) currentWriteEpoch() uint64 {
	var highest uint64
	for epoch := range s.epochs.write {
		highest = max(highest, epoch)
	}
	return highest
}

func (s *session) sendRecord(epoch uint64, typ byte, body []byte) (recordNumber, error) {
	var cid []byte
	if s.handshake.cidNegotiated {
		cid = s.handshake.peerCID
	}
	return s.sendRecordWith(epoch, typ, body, cid, s.send)
}

func (s *session) sendRecordWith(epoch uint64, typ byte, body, cid []byte, send func([]byte) error) (recordNumber, error) {
	return s.sendRecordLimited(epoch, typ, body, cid, 0, s.effectiveMTU(), send)
}

func (s *session) sendRecordLimited(epoch uint64, typ byte, body, cid []byte, padding, limit int, send func([]byte) error) (recordNumber, error) {
	w := s.epochs.write[epoch]
	if w == nil {
		return recordNumber{}, errKeyMaterial
	}
	number := recordNumber{epoch, w.sequence}
	if epoch == 0 && w.sequence >= 1<<48 || epoch != 0 && w.sequence >= w.keys.recordLimit {
		return recordNumber{}, errSequence
	}
	var packet []byte
	var err error
	if epoch == 0 {
		if padding != 0 {
			return recordNumber{}, errRecord
		}
		packet, err = encodePlainRecord(typ, number.sequence, body)
	} else {
		packet, err = w.keys.encodeRecord(number, cid, typ, body, padding)
	}
	if err != nil {
		return recordNumber{}, err
	}
	if len(packet) > limit {
		return recordNumber{}, errRecordOverflow
	}
	s.working.lastSendSize = len(packet)
	w.sequence++
	if err := send(packet); err != nil {
		return recordNumber{}, err
	}
	return number, nil
}

func fragmentBudget(mtu, cid int) int {
	n := mtu - handshakeHeader - 5 - cid - 17
	if n < 1 {
		n = 1
	}
	return min(n, maxContent-handshakeHeader)
}

func (s *session) fragmentCapacity() int {
	cid := 0
	if s.handshake.cidNegotiated {
		cid = len(s.handshake.peerCID)
	}
	return fragmentBudget(s.effectiveMTU(), cid)
}

func (s *session) startFlight(messages []handshakeMessage, now time.Time) error {
	if err := s.installKeys(); err != nil {
		return err
	}
	interval := initialRetransmit
	if s.outbound != nil {
		interval = s.outbound.interval
	}
	f, err := newFlight(messages, interval)
	if err != nil {
		return err
	}
	s.outbound = f
	return s.transmitFlight(now)
}

func (s *session) transmitFlight(now time.Time) error {
	return s.transmit(s.outbound, now)
}

func (s *session) transmit(f *flight, now time.Time) error {
	for {
		err := f.transmit(now, s.fragmentCapacity(), func(epoch uint64, body []byte) (recordNumber, error) {
			return s.sendRecord(epoch, contentHandshake, body)
		})
		if err == nil || !isMessageTooLong(err) {
			if err != nil {
				return err
			}
			if s.handshake.complete {
				return s.sendACK()
			}
			return nil
		}
		if !s.reduceHandshakeMTU(s.working.lastSendSize) {
			return err
		}
	}
}

func (s *session) receive(datagram []byte, now time.Time) ([][]byte, error) {
	from := packetPath{}
	if s.path != nil {
		from = s.path.peer
	}
	return s.receiveFrom(datagram, from, now)
}

func (s *session) receiveFrom(datagram []byte, from packetPath, now time.Time) ([][]byte, error) {
	if s.closed {
		return nil, nil
	}
	s.expireHandshakeRead(now)
	if s.path != nil && from.remote != s.path.peer.remote &&
		(!s.handshake.complete || !s.handshake.rrc || !s.handshake.cidNegotiated) {
		return nil, nil
	}
	// Rejected sources must not consume replay state or retire keys and CIDs.
	if s.path != nil && from.remote != s.path.peer.remote && !s.path.allowed(from.remote) {
		return nil, nil
	}
	var records []record
	hasCID := false
	for len(datagram) != 0 {
		r, rest, err := parseRecord(datagram, len(s.handshake.localCID))
		if err != nil {
			return nil, nil
		}
		if len(r.cid) != 0 {
			if !s.acceptCID(r.cid) {
				return nil, nil
			}
			hasCID = true
		}
		records = append(records, r)
		datagram = rest
	}
	// Demultiplexed reception includes fragments, ACKs, and duplicate records.
	if !s.handshake.complete && len(records) != 0 {
		s.handshakeReceived = now
	}
	var application [][]byte
	for _, r := range records {
		number, typ, body, ok, err := s.openRecord(r, hasCID)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if s.peerClosed != nil && recordAfter(number, *s.peerClosed) {
			continue
		}
		if s.path != nil && s.handshake.complete && r.encrypted {
			if err := s.path.observe(from, number, typ, uint64(len(r.header))+uint64(len(r.body)), now); err != nil {
				return nil, err
			}
		}
		switch typ {
		case contentHandshake:
			if err := s.receiveHandshake(number, body, now); err != nil {
				return nil, err
			}
		case contentACK:
			acks, err := parseACK(body)
			if err != nil {
				// Authenticated but malformed ACK lists are dropped.
				continue
			}
			if s.outbound != nil {
				progress := s.outbound.acknowledge(acks, r.encrypted)
				if progress && !s.outbound.complete {
					if err := s.transmitFlight(now); err != nil {
						return nil, err
					}
				}
			}
			if err := s.acknowledgePost(acks, r.encrypted, now); err != nil {
				return nil, err
			}
		case contentData:
			if number.epoch >= 3 && s.handshake.complete {
				application = append(application, body)
				s.noteMTUActivity()
			}
		case contentAlert:
			if len(body) != 2 {
				if r.encrypted {
					return nil, errDecode
				}
				continue
			}
			if body[1] == 0 {
				if s.peerClosed == nil || recordAfter(*s.peerClosed, number) {
					closedAt := number
					s.peerClosed = &closedAt
				}
				continue
			}
			if body[1] != 90 {
				return nil, alertError(body[1])
			}
		case contentRRC:
			if !s.handshake.rrc || !s.handshake.complete || number.epoch < 3 || s.path == nil {
				return nil, errUnexpectedMessage
			}
			if err := s.path.receive(from, body, uint64(len(r.header))+uint64(len(r.body)), now); err != nil {
				return nil, err
			}
			s.receiveMTUProbe(from, body, now)
		}
	}
	if err := s.advancePost(now); err != nil {
		return nil, err
	}
	if s.handshake.complete && !s.handshake.client && len(s.ack.pending) != 0 {
		if err := s.sendACK(); err != nil {
			return nil, err
		}
	}
	return application, nil
}

func (s *session) openRecord(r record, hasCID bool) (recordNumber, byte, []byte, bool, error) {
	if !r.encrypted {
		if s.epochs.installed != 0 {
			return recordNumber{}, 0, nil, false, nil
		}
		return r.number, r.typ, r.body, true, nil
	}
	if s.handshake.cidNegotiated && len(s.handshake.localCID) != 0 && !hasCID || !s.handshake.cidNegotiated && len(r.cid) != 0 {
		return recordNumber{}, 0, nil, false, nil
	}
	var epoch uint64
	var keys *readEpoch
	for candidate, k := range s.epochs.read {
		if candidate&3 == r.number.epoch && (keys == nil || candidate > epoch) {
			epoch, keys = candidate, k
		}
	}
	if keys == nil {
		return recordNumber{}, 0, nil, false, nil
	}
	number, typ, body, err := keys.keys.decodeRecord(r, epoch, r.cid, &keys.window)
	if err != nil {
		if errors.Is(err, errAuthentication) {
			if keys.failures < math.MaxUint64 {
				keys.failures++
			}
			if keys.failures >= 1<<36 {
				return recordNumber{}, 0, nil, false, errKeyMaterial
			}
			return recordNumber{}, 0, nil, false, nil
		}
		if errors.Is(err, errReplay) {
			return recordNumber{}, 0, nil, false, nil
		}
		if errors.Is(err, errRecord) {
			err = errUnexpectedMessage
		}
		return recordNumber{}, 0, nil, false, err
	}
	if epoch >= 4 {
		for old, k := range s.epochs.read {
			if old >= 3 && old < epoch {
				clear(k.secret)
				delete(s.epochs.read, old)
			}
		}
	}
	if err := s.usedLocalCID(r.cid); err != nil {
		return recordNumber{}, 0, nil, false, err
	}
	return number, typ, body, true, nil
}

func recordAfter(a, b recordNumber) bool {
	return a.epoch > b.epoch || a.epoch == b.epoch && a.sequence > b.sequence
}

func (s *session) receiveHandshake(number recordNumber, body []byte, now time.Time) error {
	accepted, err := s.reassembly.add(body, number.epoch)
	if err != nil {
		return err
	}
	if accepted {
		if err := s.queueAcknowledgement(number, now); err != nil {
			return err
		}
	}
	return s.processHandshakes(now)
}

func (s *session) queueAcknowledgement(number recordNumber, now time.Time) error {
	if len(s.ack.pending) >= maxQueuedAcknowledgements {
		if err := s.sendACK(); err != nil {
			return err
		}
	}
	if len(s.ack.pending) >= maxQueuedAcknowledgements {
		return nil
	}
	s.ack.pending = append(s.ack.pending, number)
	delay := now.Add(initialRetransmit / 4)
	// RFC 9147 §7.1: restart the 1/4-retransmit quiet timer while records
	// arrive in order, so a long flight is not ACKed while the peer is
	// still sending. Keep the first deadline once the flight is disrupted.
	if s.ack.deadline.IsZero() || !s.reassembly.disrupted() {
		s.ack.deadline = delay
	}
	if len(s.ack.pending) >= maxQueuedAcknowledgements {
		return s.sendACK()
	}
	return nil
}

func (s *session) processHandshakes(now time.Time) error {
	for {
		m, ok := s.reassembly.pop()
		if !ok {
			return nil
		}
		if s.handshake.complete {
			if err := s.receivePost(m, now); err != nil {
				return err
			}
			continue
		}
		response, err := s.handleHandshake(m)
		if err != nil {
			return err
		}
		if s.outbound != nil {
			s.outbound.finish()
		}
		if err := s.installKeys(); err != nil {
			return err
		}
		if len(response) != 0 {
			if s.currentWriteEpoch() < 2 {
				s.ack.pending = nil
				s.ack.deadline = time.Time{}
			}
			if err := s.startFlight(response, now); err != nil {
				return err
			}
		}
		if err := s.sendACK(); err != nil {
			return err
		}
	}
}

func (s *session) handshakeACKReady() bool {
	if s.handshake.complete {
		return s.handshakeFlightSent()
	}
	// RFC 9147 §7.1: ACK a disrupted flight immediately. Do not ACK a
	// complete flight that the next message will acknowledge. OpenSSL
	// SSL_accept/s_client treat ACK before Certificate as unexpected.
	return s.reassembly.disrupted()
}

func (s *session) handshakeFlightStalled(now time.Time) bool {
	if s.handshake.complete || len(s.ack.pending) == 0 || s.ack.deadline.IsZero() || now.Before(s.ack.deadline) {
		return false
	}
	// The responding flight implicitly ACKs; sending here is ACK-before-Certificate.
	if s.outbound != nil && !s.outbound.complete {
		return false
	}
	return true
}

func (s *session) handshakeACKScheduled() bool {
	if s.handshakeACKReady() {
		return true
	}
	if s.handshake.complete || len(s.ack.pending) == 0 {
		return false
	}
	if s.outbound != nil && !s.outbound.complete {
		return false
	}
	return true
}

func (s *session) sendACK() error {
	return s.writeAcknowledgements(s.handshakeACKReady())
}

func (s *session) sendScheduledACK(now time.Time) error {
	if len(s.ack.pending) == 0 {
		s.ack.deadline = time.Time{}
		return nil
	}
	return s.writeAcknowledgements(s.handshakeACKReady() || s.handshakeFlightStalled(now))
}

func (s *session) writeAcknowledgements(ready bool) error {
	if len(s.ack.pending) == 0 {
		s.ack.deadline = time.Time{}
		return nil
	}
	if !ready {
		return nil
	}
	// Split ACKs to fit the current path, including a negotiated CID.
	limit := (s.fragmentCapacity() + handshakeHeader - 2) / 16
	if limit < 1 {
		return errRecordOverflow
	}
	for len(s.ack.pending) != 0 {
		n := min(limit, len(s.ack.pending))
		body, err := encodeACK(s.ack.pending[:n])
		if err != nil {
			return err
		}
		if _, err := s.sendRecord(s.currentWriteEpoch(), contentACK, body); err != nil {
			return err
		}
		s.ack.pending = s.ack.pending[n:]
	}
	s.ack.deadline = time.Time{}
	return nil
}

func (s *session) deadline() time.Time {
	deadline := time.Time{}
	if s.handshakeACKScheduled() {
		deadline = s.ack.deadline
	}
	if !s.handshakeReadExpiry.IsZero() && (deadline.IsZero() || s.handshakeReadExpiry.Before(deadline)) {
		deadline = s.handshakeReadExpiry
	}
	if s.outbound != nil && !s.outbound.complete && (deadline.IsZero() || !s.outbound.deadline.IsZero() && s.outbound.deadline.Before(deadline)) {
		deadline = s.outbound.deadline
	}
	for _, f := range s.post {
		if !f.complete && (deadline.IsZero() || !f.deadline.IsZero() && f.deadline.Before(deadline)) {
			deadline = f.deadline
		}
	}
	if s.path != nil && s.path.probe != nil && (deadline.IsZero() || s.path.probe.deadline.Before(deadline)) {
		deadline = s.path.probe.deadline
	}
	if d := s.mtuDeadline(); !d.IsZero() && (deadline.IsZero() || d.Before(deadline)) {
		deadline = d
	}
	return deadline
}

func (s *session) tick(now time.Time) error {
	s.expireHandshakeRead(now)
	s.tickMTUProbe(now)
	if s.path != nil {
		if err := s.path.tick(now); err != nil {
			return err
		}
	}
	if !s.ack.deadline.IsZero() && !now.Before(s.ack.deadline) {
		if err := s.sendScheduledACK(now); err != nil {
			return err
		}
	}
	if s.outbound != nil {
		retransmit, err := s.outbound.expire(now)
		if err != nil {
			return err
		}
		if retransmit {
			// New-byte bursts and the first unanswered retransmit are not PMTU
			// evidence. OpenSSL often does not ACK epoch-2 fragments before
			// Finished, so shrink only after a second unanswered retry.
			if !s.outbound.pendingSend() && !s.outbound.ackedSinceSend && s.outbound.retries > 1 {
				_ = s.reduceHandshakeMTU(0)
			}
			s.outbound.ackedSinceSend = false
			if err := s.transmitFlight(now); err != nil {
				return err
			}
		}
	}
	for _, typ := range postTypes {
		if f := s.post[typ]; f != nil {
			retransmit, err := f.expire(now)
			if err != nil {
				return err
			}
			if retransmit {
				if err := s.transmit(f, now); err != nil {
					return err
				}
			}
		}
	}
	return s.advancePost(now)
}

func (s *session) handshakeFlightSent() bool {
	return s.outbound == nil || s.outbound.complete || s.outbound.sentOnce
}

func (s *session) application(body []byte) error {
	if !s.handshake.complete || s.closed {
		return errUnexpectedMessage
	}
	if s.path != nil && s.path.probe != nil {
		return errPathPending
	}
	if s.keyUpdate.localPending || s.keyUpdate.updating || !s.handshakeFlightSent() {
		return errOperationPending
	}
	w := s.epochs.write[s.currentWriteEpoch()]
	if w.sequence >= w.keys.recordLimit-1024 {
		s.keyUpdate.localPending = true
		return errOperationPending
	}
	_, err := s.sendRecord(s.currentWriteEpoch(), contentData, body)
	if err == nil {
		s.noteMTUActivity()
	} else if isMessageTooLong(err) {
		s.onApplicationTooBig()
	}
	return err
}
