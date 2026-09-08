package dtls13

import (
	"bytes"
	"errors"
	"time"
)

const (
	initialRetransmit = time.Second
	maximumRetransmit = time.Minute
	maxFlightRecords  = 65536
	maxFlightRetries  = 8
	flightBurst       = 10
)

var errHandshakeTimeout = errors.New("dtls: handshake retransmissions exhausted")

type outboundMessage struct {
	message           handshakeMessage
	acknowledged      []byte
	remaining         int
	emptyAcknowledged bool
}

type sentFragment struct {
	message    int
	start, end int
}

// A flight owns immutable messages; each transmission gets new record numbers.
type flight struct {
	messages       []outboundMessage
	sent           map[recordNumber]sentFragment
	interval       time.Duration
	deadline       time.Time
	retries        int
	complete       bool
	sentOnce       bool
	ackedSinceSend bool
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
		f.messages = append(f.messages, outboundMessage{
			message: m, acknowledged: make([]byte, (len(m.body)+7)/8), remaining: len(m.body),
		})
	}
	return f, nil
}

func (m *outboundMessage) hasByte(i int) bool {
	return m.acknowledged[i/8]&(byte(1)<<(i%8)) != 0
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
	count, err := f.sendRanges(capacity, send, true)
	if err != nil {
		return err
	}
	if count == 0 {
		_, err = f.sendRanges(capacity, send, false)
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

func (f *flight) covered(index, off int) bool {
	for _, part := range f.sent {
		if part.message == index && off >= part.start && off < part.end {
			return true
		}
	}
	return false
}

func (f *flight) messageSent(index int) bool {
	for _, part := range f.sent {
		if part.message == index {
			return true
		}
	}
	return false
}

func (f *flight) sendRanges(capacity int, send func(uint64, []byte) (recordNumber, error), onlyNew bool) (int, error) {
	count := 0
	for index := range f.messages {
		m := &f.messages[index]
		for start := 0; start < len(m.message.body) || len(m.message.body) == 0 && !m.emptyAcknowledged; {
			for start < len(m.message.body) && (m.hasByte(start) || onlyNew && f.covered(index, start)) {
				start++
			}
			if start == len(m.message.body) && len(m.message.body) != 0 {
				break
			}
			if len(m.message.body) == 0 && onlyNew && f.messageSent(index) {
				break
			}
			end := start
			for end < len(m.message.body) && end-start < capacity && !m.hasByte(end) && (!onlyNew || !f.covered(index, end)) {
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
			f.sent[number] = sentFragment{index, start, end}
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
	for i, m := range f.messages {
		if len(m.message.body) == 0 {
			if m.emptyAcknowledged {
				continue
			}
			found := false
			for _, part := range f.sent {
				if part.message == i {
					found = true
					break
				}
			}
			if !found {
				return true
			}
			continue
		}
		for off := 0; off < len(m.message.body); {
			if m.hasByte(off) {
				off++
				continue
			}
			covered := false
			for _, part := range f.sent {
				if part.message == i && off >= part.start && off < part.end {
					covered = true
					break
				}
			}
			if !covered {
				return true
			}
			off++
		}
	}
	return false
}

// acknowledge ignores unknown records and unauthenticated acknowledgements of
// protected records. Reordered ACKs for any transmission remain effective.
func (f *flight) acknowledge(records []recordNumber, authenticated bool) bool {
	if f.complete {
		return false
	}
	progress := false
	for _, number := range records {
		part, ok := f.sent[number]
		if !ok || !authenticated && number.epoch != 0 {
			continue
		}
		m := &f.messages[part.message]
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
			return progress
		}
	}
	f.finish()
	return progress
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
	if f.complete || f.deadline.IsZero() || now.Before(f.deadline) {
		return false, nil
	}
	if !f.pendingSend() {
		if f.retries == maxFlightRetries {
			return false, errHandshakeTimeout
		}
		f.retries++
		f.interval = min(2*f.interval, maximumRetransmit)
	}
	// Remaining new bytes are the next burst, not a retransmission.
	f.deadline = now.Add(f.interval)
	return true, nil
}
