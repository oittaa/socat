package dtls13

import (
	"net/netip"
	"time"
)

const (
	maxHelloEntries    = 64
	maxHelloRecords    = 128
	helloEntryCost     = 16384         // Session, ACK and bounded retransmission bookkeeping.
	maxClientHelloBody = 2*65535 + 256 // Two uint16 vectors and fixed fields.
)

// This evictable cache handles only plaintext fragments and retry flights.
// Cookie validation never depends on finding an entry here.
type pendingHello struct {
	session   *session
	started   time.Time
	credit    uint64
	replyCost int
	retry     *handshakeMessage
	verified  *serverHandshake
	message   handshakeMessage
}

func (l *Listener) removeHello(peer netip.AddrPort) {
	if p := l.hellos[peer]; p != nil {
		p.session.reassembly.clear()
		l.helloBudget.release(helloEntryCost + p.replyCost)
		delete(l.hellos, peer)
	}
}

func (l *Listener) helloRoom(cost int, keep *pendingHello) bool {
	if int64(cost) > l.helloBudget.limit {
		return false
	}
	for l.helloBudget.used.Load() > l.helloBudget.limit-int64(cost) || keep == nil && len(l.hellos) >= maxHelloEntries {
		var oldest *pendingHello
		var peer netip.AddrPort
		for address, p := range l.hellos {
			if p != keep && (oldest == nil || p.started.Before(oldest.started)) {
				oldest, peer = p, address
			}
		}
		if oldest == nil {
			return false
		}
		l.removeHello(peer)
	}
	return true
}

func (p *pendingHello) expiry(config *Config) time.Time {
	deadline := p.started.Add(cookieLifetime)
	if !config.DisableHandshakeTimeout {
		deadline = earlierDeadline(deadline, p.started.Add(config.HandshakeTimeout))
	}
	if config.HandshakeReadTimeout > 0 {
		deadline = earlierDeadline(deadline, p.session.handshakeReceived.Add(config.HandshakeReadTimeout))
	}
	return deadline
}

func earlierDeadline(a, b time.Time) time.Time {
	if a.IsZero() || !b.IsZero() && b.Before(a) {
		return b
	}
	return a
}

func (l *Listener) sendHello(p *pendingHello, peer netip.AddrPort, data []byte) error {
	if f := p.session.outbound; f != nil && len(f.sent) >= maxHelloRecords {
		return errHandshakeLimit
	}
	if uint64(len(data)) > p.credit {
		return nil
	}
	w := packetWrite{data: data, peer: peer, deadline: time.Now().Add(time.Second), stopped: l.done, result: make(chan error, 1)}
	select {
	case l.transport.writes <- w:
		p.credit -= uint64(len(data))
		l.nextPlainSequence = max(l.nextPlainSequence, p.session.write[0].sequence)
	default:
		// Congestion drops an unvalidated response without blocking the reader.
	}
	return nil
}

func (l *Listener) newHello(peer netip.AddrPort, sequence uint16, now time.Time) *pendingHello {
	if !l.helloRoom(helloEntryCost, nil) || !l.helloBudget.reserve(helloEntryCost) {
		return nil
	}
	p := &pendingHello{started: now}
	h := &handshakeState{config: l.config}
	p.session = newSession(h, func(m handshakeMessage) ([]handshakeMessage, error) {
		if m.epoch != 0 || m.typ != msgClientHello || m.sequence > 1 {
			return nil, errUnexpectedMessage
		}
		if m.sequence == 0 {
			hello, err := parseClientHello(m.body)
			if err != nil {
				return nil, err
			}
			offer, err := parseClientOffer(hello)
			if err != nil {
				return nil, err
			}
			if len(offer.cookie) != 0 {
				return nil, errIllegalParameter
			}
			retry, err := l.cookies.issue(l.config, peer, m, hello, offer, p.session.handshakeReceived)
			if err != nil {
				return nil, err
			}
			cost := 2 * fragmentCost(len(retry.body))
			if !l.helloRoom(cost, p) || !l.helloBudget.reserve(cost) {
				return nil, errHandshakeLimit
			}
			p.replyCost = cost
			p.retry = &retry
			return []handshakeMessage{retry}, nil
		}
		var err error
		p.verified, err = l.cookies.verify(l.config, peer, m, p.session.handshakeReceived)
		if err == nil {
			p.message = m
		}
		return nil, err
	}, func(data []byte) error { return l.sendHello(p, peer, data) })
	p.session.reassembly.budget = &l.helloBudget
	p.session.reassembly.next = uint32(sequence)
	p.session.handshakeReceived = now
	if sequence == 1 {
		p.session.write[0].sequence = l.nextPlainSequence
	}
	l.hellos[peer] = p
	return p
}

// Called under l.mu, after peer filtering and before allocating an association.
func (l *Listener) receiveHello(data []byte, peer netip.AddrPort, now time.Time) {
	if l.acceptErr != nil {
		return
	}
	defer func() {
		select {
		case l.helloWake <- struct{}{}:
		default:
		}
	}()
	p := l.hellos[peer]
	initial := false
	if p != nil && !now.Before(p.expiry(l.config)) {
		l.removeHello(peer)
		p = nil
	}
	// Reject impossible lengths and unrelated messages before reserving memory.
	for rest := data; len(rest) != 0; {
		r, tail, err := parseRecord(rest, l.config.ConnectionIDLength)
		if err != nil || r.encrypted || r.typ != contentHandshake && r.typ != contentACK {
			return
		}
		if r.typ == contentHandshake {
			for body := r.body; len(body) != 0; {
				f, more, err := parseFragment(body)
				if err != nil || f.typ != msgClientHello || f.sequence > 1 || f.total > maxClientHelloBody {
					return
				}
				initial = initial || f.sequence == 0
				if p == nil {
					p = l.newHello(peer, f.sequence, now)
					if p == nil {
						return
					}
				}
				if uint32(f.sequence) >= p.session.reassembly.next && p.session.reassembly.pending[f.sequence] == nil &&
					!l.helloRoom(fragmentCost(f.total), p) {
					return
				}
				body = more
			}
		}
		rest = tail
	}
	if p == nil {
		return
	}
	p.credit = min(p.credit+3*uint64(len(data)), 3*maxClientHelloBody)
	if _, err := p.session.receive(data, now); err != nil {
		_, _ = p.session.sendRecord(0, contentAlert, errorAlert(err))
		l.removeHello(peer)
	} else if p.verified != nil {
		l.admitHello(peer, p)
		l.removeHello(peer)
	} else if initial && p.retry != nil && p.session.outbound != nil && p.session.outbound.complete {
		// An unauthenticated ACK must not suppress a subsequent CH1 retry.
		if err := p.session.startFlight([]handshakeMessage{*p.retry}, now); err != nil {
			l.removeHello(peer)
		}
	}
}

func (l *Listener) admitHello(peer netip.AddrPort, p *pendingHello) {
	if len(l.connections) >= l.config.MaxConnections || len(l.handshakes) >= 16 {
		return
	}
	h := p.verified
	if len(h.localCID) != 0 && l.cids[string(h.localCID)] != nil {
		return
	}
	c := newConn(peer)
	c.cookieValidated = true
	c.transport, c.packetBudget = l.transport, &l.packets
	s := newSession(h.handshakeState, h.handle, c.sendPacket)
	s.reassembly.budget, s.reassembly.next = &l.fragments, 1
	fragment, err := p.message.fragment(0, len(p.message.body))
	if err != nil {
		return
	}
	if ok, err := s.reassembly.add(fragment, 0); err != nil || !ok {
		s.reassembly.clear()
		return
	}
	// Later plaintext ACKs must not acknowledge records from the retry cache.
	s.write[0].sequence = l.nextPlainSequence
	c.attach(s)
	c.onReady, c.onClose, c.onPeerChanged = l.establish, l.remove, l.peerChanged
	s.setLocalCIDs = func(ids [][]byte) error { return l.setCIDs(c, ids) }
	l.connections[c], l.handshakes[peer] = true, c
	if len(h.localCID) != 0 {
		l.cids[string(h.localCID)] = c
	}
	go c.run()
}

// One timer services all evictable entries; unauthenticated peers get no goroutine.
func (l *Listener) runHelloTimers() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		l.mu.Lock()
		if l.err != nil {
			l.mu.Unlock()
			return
		}
		now := time.Now()
		var deadline time.Time
		for peer, p := range l.hellos {
			if !now.Before(p.expiry(l.config)) {
				l.removeHello(peer)
				continue
			}
			if err := p.session.tick(now); err != nil {
				l.removeHello(peer)
				continue
			}
			deadline = earlierDeadline(deadline, earlierDeadline(p.expiry(l.config), p.session.deadline()))
		}
		l.mu.Unlock()
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			timer.Reset(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case <-l.done:
			return
		case <-l.helloWake:
		case <-timeout:
		}
	}
}
