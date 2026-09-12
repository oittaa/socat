package dtls13

import (
	"bytes"
	"errors"
	"time"
)

const (
	initialRetransmit = time.Second
	maximumRetransmit = time.Minute
	// Floor after RFC 9147 §5.8.2's 1.5×RTT adjustment, so a LAN sample
	// does not arm a millisecond retransmit timer.
	minRetransmit    = 100 * time.Millisecond
	maxFlightRecords = 65536
	maxFlightRetries = 8
	flightBurst      = 10
)

var errHandshakeTimeout = errors.New("dtls: handshake retransmissions exhausted")

type outboundMessage struct {
	message           handshakeMessage
	acknowledged      []byte
	sent              []byte
	remaining         int
	sentCount         int
	emptyAcknowledged bool
	emptySent         bool
	resent            bool
}

type sentFragment struct {
	message    int
	start, end int
	sentAt     time.Time
}

// A flight owns immutable messages; each transmission gets new record numbers.
type flight struct {
	messages       []outboundMessage
	sent           map[recordNumber]sentFragment
	interval       time.Duration
	deadline       time.Time
	firstSent      time.Time
	retries        int
	complete       bool
	sentOnce       bool
	ackedSinceSend bool
	resent         bool
	burstWait      bool
}

func newFlight(messages []handshakeMessage, interval time.Duration) (*flight, error) {
	if len(messages) == 0 || len(messages) > maxPendingMessages {
		return nil, errHandshakeLimit
	}
	if interval <= 0 {
		interval = initialRetransmit
	}
	if interval > maximumRetransmit {
		interval = maximumRetransmit
	}
	f := &flight{interval: interval, sent: make(map[recordNumber]sentFragment)}
	total := 0
	for _, m := range messages {
		total += len(m.body)
		if len(m.body) > maxHandshakeBody || total > 2*maxHandshakeBody {
			return nil, errHandshakeLimit
		}
		m.body = bytes.Clone(m.body)
		bitBytes := (len(m.body) + 7) / 8
		f.messages = append(f.messages, outboundMessage{
			message: m, acknowledged: make([]byte, bitBytes), sent: make([]byte, bitBytes), remaining: len(m.body),
		})
	}
	return f, nil
}

func (m *outboundMessage) hasByte(i int) bool {
	return m.acknowledged[i/8]&(byte(1)<<(i%8)) != 0
}

func (m *outboundMessage) hasSent(i int) bool {
	return m.sent[i/8]&(byte(1)<<(i%8)) != 0
}

// transmit sends at most ten records. New bytes are sent before unacked
// retransmissions so a large authenticated flight can finish without ACKs.
func (f *flight) transmit(now time.Time, capacity int, send func(uint64, []byte) (recordNumber, error)) error {
	if f.complete {
		return nil
	}
	if capacity < 1 || capacity > maxContent-handshakeHeader {
		return errRecordOverflow
	}
	count, err := f.sendRanges(now, capacity, send, true)
	if err != nil {
		return err
	}
	if count == 0 {
		_, err = f.sendRanges(now, capacity, send, false)
		if err != nil {
			return err
		}
	}
	if !f.pendingSend() {
		f.sentOnce = true
	}
	f.deadline = now.Add(f.interval)
	return nil
}

func (f *flight) sendRanges(now time.Time, capacity int, send func(uint64, []byte) (recordNumber, error), onlyNew bool) (int, error) {
	count := 0
	for index := range f.messages {
		m := &f.messages[index]
		for start := 0; start < len(m.message.body) || len(m.message.body) == 0 && !m.emptyAcknowledged; {
			for start < len(m.message.body) && (m.hasByte(start) || onlyNew && m.hasSent(start)) {
				start++
			}
			if start == len(m.message.body) && len(m.message.body) != 0 {
				break
			}
			if len(m.message.body) == 0 && onlyNew && m.emptySent {
				break
			}
			end := start
			for end < len(m.message.body) && end-start < capacity && !m.hasByte(end) && (!onlyNew || !m.hasSent(end)) {
				end++
			}
			if len(f.sent) >= maxFlightRecords {
				return count, errHandshakeLimit
			}
			body, err := m.message.fragment(start, end-start)
			if err != nil {
				return count, err
			}
			number, err := send(m.message.epoch, body)
			if err != nil {
				return count, err
			}
			if number.epoch != m.message.epoch {
				return count, errRecord
			}
			if _, exists := f.sent[number]; exists {
				return count, errSequence
			}
			if f.firstSent.IsZero() {
				f.firstSent = now
			}
			if !onlyNew {
				m.resent = true
				f.resent = true
			}
			f.sent[number] = sentFragment{message: index, start: start, end: end, sentAt: now}
			if len(m.message.body) == 0 {
				m.emptySent = true
			} else {
				for i := start; i < end; i++ {
					if !m.hasSent(i) {
						m.sent[i/8] |= byte(1) << (i % 8)
						m.sentCount++
					}
				}
			}
			count++
			if count == flightBurst {
				return count, nil
			}
			if len(m.message.body) == 0 {
				break
			}
			start = end
		}
	}
	return count, nil
}

func (f *flight) pendingSend() bool {
	for i := range f.messages {
		m := &f.messages[i]
		if len(m.message.body) == 0 {
			if !m.emptyAcknowledged && !m.emptySent {
				return true
			}
			continue
		}
		if m.sentCount < len(m.message.body) {
			return true
		}
	}
	return false
}

// acknowledge ignores unknown records and unauthenticated acknowledgements of
// protected records. Reordered ACKs for any transmission remain effective.
func (f *flight) acknowledge(records []recordNumber, authenticated bool, now time.Time) (bool, time.Duration) {
	if f.complete {
		return false, 0
	}
	progress := false
	var rtt time.Duration
	for _, number := range records {
		part, ok := f.sent[number]
		if !ok || !authenticated && number.epoch != 0 {
			continue
		}
		m := &f.messages[part.message]
		if authenticated && !m.resent && !part.sentAt.IsZero() && now.After(part.sentAt) {
			if sample := now.Sub(part.sentAt); rtt == 0 || sample < rtt {
				rtt = sample
			}
		}
		if len(m.message.body) == 0 && !m.emptyAcknowledged {
			m.emptyAcknowledged = true
			progress = true
		}
		for i := part.start; i < part.end; i++ {
			if !m.hasByte(i) {
				m.acknowledged[i/8] |= byte(1) << (i % 8)
				m.remaining--
				progress = true
			}
		}
		delete(f.sent, number)
	}
	if progress {
		f.retries = 0
		f.ackedSinceSend = true
	}
	for _, m := range f.messages {
		if m.remaining != 0 || len(m.message.body) == 0 && !m.emptyAcknowledged {
			return progress, rtt
		}
	}
	f.finish()
	return progress, rtt
}

func (f *flight) finish() {
	f.complete = true
	f.deadline = time.Time{}
	f.messages = nil
	f.sent = nil
}

// expire advances a timer supplied by the connection's event loop. Tests can
// drive the same transitions with a synthetic clock.
func (f *flight) expire(now time.Time) (bool, error) {
	if f == nil || f.complete || f.deadline.IsZero() || now.Before(f.deadline) {
		return false, nil
	}
	if !f.pendingSend() {
		if f.retries == maxFlightRetries {
			return false, errHandshakeTimeout
		}
		f.retries++
		f.resent = true
		f.interval = min(2*f.interval, maximumRetransmit)
	} else {
		f.burstWait = true
	}
	// Remaining new bytes are the next burst, not a retransmission.
	f.deadline = now.Add(f.interval)
	return true, nil
}

func flightDeadline(f *flight) time.Time {
	if f == nil || f.complete {
		return time.Time{}
	}
	return f.deadline
}
