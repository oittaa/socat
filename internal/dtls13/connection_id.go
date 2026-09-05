package dtls13

import (
	"bytes"
	"crypto/rand"
	"slices"
	"time"
)

const maxConnectionIDs = 8

func containsCID(ids [][]byte, cid []byte) bool {
	return slices.ContainsFunc(ids, func(id []byte) bool { return bytes.Equal(id, cid) })
}

func (s *session) acceptCID(cid []byte) bool {
	if s.localCIDs == nil {
		return bytes.Equal(cid, s.handshake.localCID)
	}
	return containsCID(s.localCIDs, cid)
}

func (s *session) usedLocalCID(cid []byte) error {
	if len(s.immediateCIDs) == 0 || !containsCID(s.immediateCIDs, cid) {
		return nil
	}
	if s.setLocalCIDs != nil {
		if err := s.setLocalCIDs(s.immediateCIDs); err != nil {
			return err
		}
	}
	s.localCIDs = s.immediateCIDs
	s.immediateCIDs = nil
	return nil
}

func (s *session) requestCIDs(count byte, now time.Time) error {
	if !s.handshake.cidNegotiated || len(s.handshake.peerCID) == 0 {
		return errUnexpectedMessage
	}
	if s.cidRequested {
		return errUpdatePending
	}
	if err := s.startPost(msgRequestConnectionID, []byte{count}, now); err != nil {
		return err
	}
	s.cidRequested = true
	return nil
}

func (s *session) provideCIDs(count int, immediate bool, now time.Time) error {
	if !s.handshake.cidNegotiated || len(s.handshake.localCID) == 0 {
		return errUnexpectedMessage
	}
	if s.updating || s.outbound != nil && !s.outbound.complete || s.post[msgNewConnectionID] != nil || len(s.immediateCIDs) != 0 {
		return errUpdatePending
	}
	if s.localCIDs == nil {
		s.localCIDs = [][]byte{bytes.Clone(s.handshake.localCID)}
	}
	count = min(max(count, 0), maxConnectionIDs-len(s.localCIDs))
	// One additional ID permits immediate rotation of a full spare pool.
	if immediate {
		count = 1
	}
	ids := make([][]byte, 0, count)
	for len(ids) < count {
		id := make([]byte, len(s.handshake.localCID))
		if _, err := rand.Read(id); err != nil {
			return err
		}
		if !containsCID(s.localCIDs, id) && !containsCID(ids, id) {
			ids = append(ids, id)
		}
	}
	body, err := encodeCIDs(ids, immediate)
	if err != nil {
		return err
	}
	updated := append(slices.Clone(s.localCIDs), ids...)
	if s.setLocalCIDs != nil {
		if err := s.setLocalCIDs(updated); err != nil {
			return err
		}
	}
	s.localCIDs = updated
	if immediate {
		s.immediateCIDs = ids
	}
	return s.startPost(msgNewConnectionID, body, now)
}

func encodeCIDs(ids [][]byte, immediate bool) ([]byte, error) {
	list := wireWriter{}
	for _, id := range ids {
		list.vector8(id)
	}
	if list.err != nil {
		return nil, list.err
	}
	w := wireWriter{}
	w.vector16(list.data)
	usage := byte(1)
	if immediate {
		if len(ids) == 0 {
			return nil, errIllegalParameter
		}
		usage = 0
	}
	w.uint8(usage)
	return w.result()
}

func parseCIDs(body []byte) ([][]byte, bool, error) {
	r := wireReader{data: body}
	list := wireReader{data: r.vector16()}
	usage := r.uint8()
	if r.done() != nil {
		return nil, false, errDecode
	}
	if usage > 1 || usage == 0 && len(list.data) == 0 {
		return nil, false, errIllegalParameter
	}
	var ids [][]byte
	for len(list.data) != 0 {
		id := list.vector8()
		if list.err != nil {
			return nil, false, errDecode
		}
		if len(ids) < maxConnectionIDs && !containsCID(ids, id) {
			ids = append(ids, bytes.Clone(id))
		}
	}
	return ids, usage == 0, nil
}

func (s *session) receiveCIDs(body []byte) error {
	// Eligibility depends on the handshake, not a later zero-length rotation.
	if !s.handshake.peerCIDUpdates {
		return errUnexpectedMessage
	}
	ids, immediate, err := parseCIDs(body)
	if err != nil {
		return err
	}
	if immediate {
		s.handshake.peerCID = ids[0]
		s.peerSpareCIDs = ids[1:]
		// Immediate rotation also supersedes the CID reserved for a new path.
		if s.path != nil && s.path.probe != nil && !s.path.probe.old {
			s.path.probe.cid = ids[0]
		}
	} else {
		for _, id := range ids {
			if len(s.peerSpareCIDs) < maxConnectionIDs && !bytes.Equal(id, s.handshake.peerCID) && !containsCID(s.peerSpareCIDs, id) {
				s.peerSpareCIDs = append(s.peerSpareCIDs, id)
			}
		}
		s.cidRequested = false
	}
	return s.sendACK()
}

func (s *session) useSpareCID() {
	if len(s.peerSpareCIDs) != 0 {
		s.handshake.peerCID = s.peerSpareCIDs[0]
		s.peerSpareCIDs = s.peerSpareCIDs[1:]
		s.wantCIDs = len(s.peerSpareCIDs) < 2
	}
}
