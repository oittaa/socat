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
	if s.cid.local == nil {
		return bytes.Equal(cid, s.handshake.localCID)
	}
	return containsCID(s.cid.local, cid)
}

func (s *session) usedLocalCID(cid []byte) error {
	if len(s.cid.immediate) == 0 || !containsCID(s.cid.immediate, cid) {
		return nil
	}
	if s.cid.setLocal != nil {
		if err := s.cid.setLocal(s.cid.immediate); err != nil {
			return err
		}
	}
	s.cid.local = s.cid.immediate
	s.cid.immediate = nil
	return nil
}

func (s *session) requestCIDs(count byte, now time.Time) error {
	if !s.handshake.cidNegotiated || len(s.handshake.peerCID) == 0 {
		return errUnexpectedMessage
	}
	if s.cid.requested {
		return errOperationPending
	}
	if err := s.startPost(msgRequestConnectionID, []byte{count}, now); err != nil {
		return err
	}
	s.cid.requested = true
	return nil
}

func (s *session) cidBusy() bool {
	return s.keyUpdate.updating || s.outbound != nil && !s.outbound.complete || s.post[msgNewConnectionID] != nil || len(s.cid.immediate) != 0 || s.path != nil && s.path.probe != nil
}

// respondCIDRequest issues spares for a pending RequestConnectionId.
// A full issuance pool rotates one CID immediately instead of sending an
// empty spare list; the spare request stays pending until capacity exists.
func (s *session) respondCIDRequest(now time.Time) error {
	if s.cid.response == nil || s.cidBusy() {
		return nil
	}
	if s.cid.local == nil {
		s.cid.local = [][]byte{bytes.Clone(s.handshake.localCID)}
	}
	if len(s.cid.local) >= maxConnectionIDs && *s.cid.response > 0 {
		return s.provideCIDs(1, true, now)
	}
	count := *s.cid.response
	s.cid.response = nil
	return s.provideCIDs(int(count), false, now)
}

func (s *session) provideCIDs(count int, immediate bool, now time.Time) error {
	if !s.handshake.cidNegotiated || len(s.handshake.localCID) == 0 {
		return errUnexpectedMessage
	}
	if s.cidBusy() {
		return errOperationPending
	}
	if s.cid.local == nil {
		s.cid.local = [][]byte{bytes.Clone(s.handshake.localCID)}
	}
	count = min(max(count, 0), maxConnectionIDs-len(s.cid.local))
	if immediate {
		count = 1
	}
	ids := make([][]byte, 0, count)
	for len(ids) < count {
		id := make([]byte, len(s.handshake.localCID))
		if _, err := rand.Read(id); err != nil {
			return err
		}
		if !containsCID(s.cid.local, id) && !containsCID(ids, id) {
			ids = append(ids, id)
		}
	}
	body, err := encodeCIDs(ids, immediate)
	if err != nil {
		return err
	}
	updated := append(slices.Clone(s.cid.local), ids...)
	if s.cid.setLocal != nil {
		if err := s.cid.setLocal(updated); err != nil {
			return err
		}
	}
	s.cid.local = updated
	if immediate {
		s.cid.immediate = ids
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
		s.cid.peerSpare = ids[1:]
		// Immediate rotation also supersedes the CID reserved for a new path.
		if s.path != nil && s.path.probe != nil && s.path.probe.phase == pathValidateCandidate {
			s.path.probe.cid = ids[0]
		}
	} else {
		for _, id := range ids {
			if len(s.cid.peerSpare) < maxConnectionIDs && !bytes.Equal(id, s.handshake.peerCID) && !containsCID(s.cid.peerSpare, id) {
				s.cid.peerSpare = append(s.cid.peerSpare, id)
			}
		}
		s.cid.requested = false
	}
	return s.sendACK()
}
