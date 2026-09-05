package dtls13

import (
	"errors"
	"fmt"
)

const (
	handshakeHeader    = 12
	maxHandshakeBody   = 1 << 20
	maxPendingMessages = 16
)

var (
	errHandshakeLimit   = errors.New("dtls: handshake resource limit exceeded")
	errFragmentConflict = fmt.Errorf("%w: inconsistent handshake fragment", errIllegalParameter)
)

type handshakeMessage struct {
	typ      byte
	sequence uint16
	epoch    uint64
	body     []byte
}

func (m handshakeMessage) transcript() ([]byte, error) {
	if len(m.body) > maxHandshakeBody {
		return nil, errHandshakeLimit
	}
	w := wireWriter{}
	w.uint8(m.typ)
	w.vector24(m.body)
	return w.result()
}

func (m handshakeMessage) fragment(offset, length int) ([]byte, error) {
	if len(m.body) > maxHandshakeBody {
		return nil, errHandshakeLimit
	}
	if offset < 0 || offset > len(m.body) || length < 0 || length > len(m.body)-offset {
		return nil, errDecode
	}
	w := wireWriter{}
	w.uint8(m.typ)
	w.uint24(len(m.body))
	w.uint16(m.sequence)
	w.uint24(offset)
	w.vector24(m.body[offset : offset+length])
	return w.result()
}

type handshakeFragment struct {
	typ           byte
	sequence      uint16
	total, offset int
	body          []byte
}

func parseFragment(data []byte) (handshakeFragment, []byte, error) {
	r := wireReader{data: data}
	f := handshakeFragment{typ: r.uint8(), total: r.uint24(), sequence: r.uint16()}
	f.offset = r.uint24()
	f.body = r.vector24()
	if r.err != nil || f.offset > f.total || len(f.body) > f.total-f.offset {
		return handshakeFragment{}, nil, errDecode
	}
	return f, r.data, nil
}

type partialHandshake struct {
	message   handshakeMessage
	seen      []byte
	remaining int
}

type reassembler struct {
	next     uint32
	pending  map[uint16]*partialHandshake
	buffered int
	budget   *memoryBudget
}

// add reports whether every fragment was buffered or previously processed.
// A discarded future fragment must not be acknowledged by the caller.
func (r *reassembler) add(data []byte, epoch uint64) (bool, error) {
	if len(data) == 0 {
		return false, errDecode
	}
	accepted := true
	for len(data) != 0 {
		f, rest, err := parseFragment(data)
		if err != nil {
			return false, err
		}
		data = rest
		ok, err := r.insert(f, epoch)
		if err != nil {
			return false, err
		}
		accepted = accepted && ok
	}
	return accepted, nil
}

func (r *reassembler) insert(f handshakeFragment, epoch uint64) (bool, error) {
	if uint32(f.sequence) < r.next {
		return true, nil
	}
	if uint32(f.sequence)-r.next >= maxPendingMessages {
		return false, nil
	}
	if f.total > maxHandshakeBody {
		return false, errHandshakeLimit
	}
	p := r.pending[f.sequence]
	if p == nil {
		// Reserve one maximum-sized message for the next expected sequence.
		futureBytes := r.buffered
		if next := r.pending[uint16(r.next&0xffff)]; next != nil {
			futureBytes -= len(next.message.body)
		}
		if uint32(f.sequence) != r.next && futureBytes+f.total > maxHandshakeBody {
			return false, nil
		}
		if !r.budget.reserve(fragmentCost(f.total)) {
			return false, nil
		}
		if r.pending == nil {
			r.pending = make(map[uint16]*partialHandshake)
		}
		p = &partialHandshake{
			message: handshakeMessage{f.typ, f.sequence, epoch, make([]byte, f.total)},
			seen:    make([]byte, (f.total+7)/8), remaining: f.total,
		}
		r.pending[f.sequence] = p
		r.buffered += f.total
	}
	if p.message.typ != f.typ || p.message.epoch != epoch || len(p.message.body) != f.total {
		return false, errFragmentConflict
	}
	for i, b := range f.body {
		position := f.offset + i
		mask := byte(1) << (position % 8)
		if p.seen[position/8]&mask != 0 {
			if p.message.body[position] != b {
				return false, errFragmentConflict
			}
			continue
		}
		p.seen[position/8] |= mask
		p.message.body[position] = b
		p.remaining--
	}
	return true, nil
}

func (r *reassembler) pop() (handshakeMessage, bool) {
	if r.next > 65535 {
		return handshakeMessage{}, false
	}
	p := r.pending[uint16(r.next)]
	if p == nil || p.remaining != 0 {
		return handshakeMessage{}, false
	}
	delete(r.pending, uint16(r.next))
	r.next++
	r.buffered -= len(p.message.body)
	r.budget.release(fragmentCost(len(p.message.body)))
	return p.message, true
}

func fragmentCost(size int) int { return size + (size+7)/8 + 128 }

func (r *reassembler) clear() {
	for _, p := range r.pending {
		r.budget.release(fragmentCost(len(p.message.body)))
	}
	r.pending = nil
	r.buffered = 0
}
