package dtls13

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net/netip"
	"time"
)

const (
	pathChallenge = byte(0)
	pathResponse  = byte(1)
	pathDrop      = byte(2)
)

var errPathPending = errors.New("dtls: waiting for peer address validation")

// local identifies the receiving socket, including a retained migration socket.
type packetPath struct {
	remote netip.AddrPort
	local  uint64
}

type pathProbe struct {
	candidate packetPath
	old       bool
	cookie    [8]byte
	deadline  time.Time
	credit    uint64
	cid       []byte
}

type pathState struct {
	session   *session
	peer      packetPath
	probe     *pathProbe
	highest   recordNumber
	seen      bool
	send      func(packetPath, []byte) error
	allowPeer func(netip.AddrPort) bool
	changed   func(packetPath)
}

func (p *pathState) allowed(address netip.AddrPort) bool {
	return address.IsValid() && (p.allowPeer == nil || p.allowPeer(address))
}

func (p *pathState) observe(from packetPath, number recordNumber, typ byte, size uint64, now time.Time) error {
	newest := !p.seen || recordAfter(number, p.highest)
	if newest {
		p.highest, p.seen = number, true
	}
	if from.remote == p.peer.remote || number.epoch < 3 || typ == contentRRC {
		return nil
	}
	if p.probe != nil {
		if from == p.probe.candidate {
			p.probe.credit = min(1<<30, p.probe.credit+3*size)
		}
		return nil
	}
	// Responses do not themselves start another validation exchange.
	if !newest || !p.allowed(from.remote) {
		return nil
	}
	p.probe = &pathProbe{candidate: from, old: true, credit: 3 * size}
	return p.challenge(now)
}

func (p *pathState) challenge(now time.Time) error {
	if _, err := rand.Read(p.probe.cookie[:]); err != nil {
		return err
	}
	p.probe.deadline = now.Add(time.Second)
	destination := p.peer
	if !p.probe.old {
		destination = p.probe.candidate
	}
	return p.sendMessage(destination, pathChallenge, p.probe.cookie[:], 0)
}

func (p *pathState) startBasic(now time.Time) error {
	p.probe.old = false
	if len(p.session.peerSpareCIDs) != 0 {
		p.probe.cid = p.session.peerSpareCIDs[0]
		p.session.peerSpareCIDs = p.session.peerSpareCIDs[1:]
		p.session.wantCIDs = len(p.session.peerSpareCIDs) < 2
	} else {
		p.probe.cid = bytes.Clone(p.session.handshake.peerCID)
	}
	return p.challenge(now)
}

func (p *pathState) receive(from packetPath, body []byte, size uint64, now time.Time) error {
	if len(body) == 0 {
		return errDecode
	}
	if body[0] > pathDrop {
		return nil
	}
	if len(body) != 9 {
		return errDecode
	}
	if body[0] == pathChallenge {
		if p.probe != nil && from == p.probe.candidate {
			p.probe.credit = min(1<<30, p.probe.credit+3*size)
		}
		response := pathResponse
		if from.local != p.peer.local {
			response = pathDrop
		}
		return p.sendMessage(from, response, body[1:], 3*size)
	}
	probe := p.probe
	if probe == nil || !bytes.Equal(body[1:], probe.cookie[:]) || !now.Before(probe.deadline) {
		return nil
	}
	expected := probe.candidate
	if probe.old {
		expected = p.peer
	}
	if from != expected {
		return nil
	}
	if body[0] == pathDrop {
		if probe.old {
			return p.startBasic(now)
		}
		return nil
	}
	if !probe.old {
		p.peer = probe.candidate
		p.session.handshake.peerCID = probe.cid
		if p.changed != nil {
			p.changed(p.peer)
		}
	}
	p.probe = nil
	return nil
}

func (p *pathState) sendMessage(to packetPath, typ byte, cookie []byte, credit uint64) error {
	cid := p.session.handshake.peerCID
	probe := p.probe
	if probe != nil && to == probe.candidate && !probe.old {
		cid = probe.cid
	}
	body := append([]byte{typ}, cookie...)
	_, err := p.session.sendRecordWith(p.session.currentWriteEpoch(), contentRRC, body, cid, func(packet []byte) error {
		if to.remote != p.peer.remote {
			if probe != nil && to == probe.candidate {
				if uint64(len(packet)) > probe.credit {
					return nil
				}
				probe.credit -= uint64(len(packet))
			} else if uint64(len(packet)) > credit {
				return nil
			}
		}
		return p.send(to, packet)
	})
	return err
}

func (p *pathState) tick(now time.Time) error {
	if p.probe == nil || now.Before(p.probe.deadline) {
		return nil
	}
	if p.probe.old {
		return p.startBasic(now)
	}
	p.probe = nil
	return nil
}
