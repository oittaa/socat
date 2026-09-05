package dtls13

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"slices"
	"strings"
)

type clientHandshake struct {
	*handshakeState
	hello                  clientHello
	firstHello, retryHello []byte
	shares                 map[uint16]*keyShare
	phase                  byte
	retried                bool
	retrySuite             uint16
	requestedCertificate   bool
	certificateSignatures  []uint16
	authorities            [][]byte
}

func newClientHandshake(config *Config) (*clientHandshake, []handshakeMessage, error) {
	state, err := newHandshakeState(config, true)
	if err != nil {
		return nil, nil, err
	}
	h := &clientHandshake{handshakeState: state, shares: make(map[uint16]*keyShare), phase: msgServerHello}
	h.hello = clientHello{suites: slices.Clone(state.config.CipherSuites), extensions: extensions{extSupportedVersions: {2, 0xfe, 0xfc}}}
	if _, err := rand.Read(h.hello.random[:]); err != nil {
		return nil, nil, err
	}
	groups := make([]uint16, 0, len(state.config.CurvePreferences))
	keyShares := wireWriter{}
	for i, group := range state.config.CurvePreferences {
		id := uint16(group)
		groups = append(groups, id)
		// Send the preferred share and a small X25519 fallback. Other groups use HRR.
		if i != 0 && id != groupX25519 {
			continue
		}
		private, err := generateShare(id)
		if err != nil {
			return nil, nil, err
		}
		h.shares[id] = private
		share, err := encodeKeyShare(id, private.public)
		if err != nil {
			return nil, nil, err
		}
		keyShares.data = append(keyShares.data, share...)
	}
	groupList, err := encodeList16(groups)
	if err != nil {
		return nil, nil, err
	}
	h.hello.extensions[extSupportedGroups] = groupList
	shareList := wireWriter{}
	shareList.vector16(keyShares.data)
	h.hello.extensions[extKeyShare] = shareList.data
	signatures, err := encodeList16(signatureSchemes)
	if err != nil {
		return nil, nil, err
	}
	h.hello.extensions[extSignatureAlgorithms] = signatures
	if name := strings.TrimSuffix(h.config.ServerName, "."); name != "" && net.ParseIP(name) == nil {
		encoded, err := encodeServerName(name)
		if err != nil {
			return nil, nil, err
		}
		h.hello.extensions[extServerName] = encoded
	}
	if len(h.config.NextProtos) != 0 {
		encoded, err := encodeALPN(h.config.NextProtos)
		if err != nil {
			return nil, nil, err
		}
		h.hello.extensions[extALPN] = encoded
	}
	if len(h.localCID) != 0 {
		cid := wireWriter{}
		cid.vector8(h.localCID)
		h.hello.extensions[extConnectionID] = cid.data
		h.hello.extensions[extRRC] = nil
	}
	body, err := h.hello.marshal()
	if err != nil {
		return nil, nil, err
	}
	m, err := h.message(msgClientHello, 0, body)
	if err != nil {
		return nil, nil, err
	}
	h.firstHello, err = m.transcript()
	if err != nil {
		return nil, nil, err
	}
	return h, []handshakeMessage{m}, nil
}

func (h *clientHandshake) handle(m handshakeMessage) ([]handshakeMessage, error) {
	if h.complete {
		return nil, errUnexpectedMessage
	}
	if h.phase == msgServerHello {
		if m.typ != msgServerHello || m.epoch != 0 {
			return nil, errUnexpectedMessage
		}
		return h.serverHello(m)
	}
	if m.epoch != 2 {
		return nil, errUnexpectedMessage
	}
	switch h.phase {
	case msgEncryptedExtensions:
		if m.typ != msgEncryptedExtensions {
			return nil, errUnexpectedMessage
		}
		if err := h.encryptedExtensions(m); err != nil {
			return nil, err
		}
		h.phase = msgCertificateRequest
	case msgCertificateRequest:
		if m.typ == msgCertificateRequest {
			var err error
			h.certificateSignatures, h.authorities, err = parseCertificateRequest(m.body)
			if err != nil {
				return nil, err
			}
			h.requestedCertificate = true
			if err := h.schedule.write(m); err != nil {
				return nil, err
			}
			h.phase = msgCertificate
			return nil, nil
		}
		if m.typ != msgCertificate {
			return nil, errUnexpectedMessage
		}
		if err := h.peerCertificate(m); err != nil {
			return nil, err
		}
		h.phase = msgCertificateVerify
	case msgCertificate:
		if m.typ != msgCertificate {
			return nil, errUnexpectedMessage
		}
		if err := h.peerCertificate(m); err != nil {
			return nil, err
		}
		h.phase = msgCertificateVerify
	case msgCertificateVerify:
		if m.typ != msgCertificateVerify {
			return nil, errUnexpectedMessage
		}
		if err := h.peerCertificateVerify(m, signatureSchemes); err != nil {
			return nil, err
		}
		h.phase = msgFinished
	case msgFinished:
		if m.typ != msgFinished {
			return nil, errUnexpectedMessage
		}
		if err := h.peerFinished(m); err != nil {
			return nil, err
		}
		return h.finalFlight()
	default:
		return nil, errUnexpectedMessage
	}
	return nil, nil
}

func (h *clientHandshake) serverHello(m handshakeMessage) ([]handshakeMessage, error) {
	hello, err := parseServerHello(m.body)
	if err != nil {
		return nil, err
	}
	if len(hello.sessionID) != 0 || !slices.Contains(h.hello.suites, hello.suite) {
		return nil, errIllegalParameter
	}
	if h.retried && hello.suite != h.retrySuite {
		return nil, errIllegalParameter
	}
	version, ok := hello.extensions[extSupportedVersions]
	if !ok {
		return nil, errProtocolVersion
	}
	if len(version) != 2 {
		return nil, errDecode
	}
	if binary.BigEndian.Uint16(version) != version13 {
		return nil, errIllegalParameter
	}
	if hello.retry() {
		return h.retryRequest(m, hello)
	}
	for id := range hello.extensions {
		if _, ok := h.hello.extensions[id]; !ok {
			return nil, errUnsupportedExtension
		}
		if id != extSupportedVersions && id != extKeyShare && id != extConnectionID && id != extRRC {
			return nil, errIllegalParameter
		}
	}
	group, public, err := parseServerShare(hello.extensions[extKeyShare])
	if err != nil {
		return nil, err
	}
	private := h.shares[group]
	if private == nil {
		return nil, errIllegalParameter
	}
	shared, err := private.shared(public)
	if err != nil {
		return nil, err
	}
	if cid, ok := hello.extensions[extConnectionID]; ok {
		h.peerCID, err = parseConnectionID(cid)
		if err != nil {
			return nil, err
		}
		h.cidNegotiated = true
	}
	if rrc, ok := hello.extensions[extRRC]; ok {
		if len(rrc) != 0 || !h.cidNegotiated {
			return nil, errIllegalParameter
		}
		h.rrc = true
	}
	transcript := slices.Clone(h.firstHello)
	if h.retried {
		body, err := h.hello.marshal()
		if err != nil {
			return nil, err
		}
		second, err := (handshakeMessage{typ: msgClientHello, body: body}).transcript()
		if err != nil {
			return nil, err
		}
		transcript, err = retryTranscript(hello.suite, h.firstHello, h.retryHello, second)
		if err != nil {
			return nil, err
		}
	}
	server, err := m.transcript()
	if err != nil {
		return nil, err
	}
	transcript = append(transcript, server...)
	h.schedule, err = newKeySchedule(hello.suite, shared, transcript)
	clear(shared)
	if err != nil {
		return nil, err
	}
	h.shares = nil
	h.state.CipherSuite = hello.suite
	h.state.CurveID = private.group.id
	h.phase = msgEncryptedExtensions
	return nil, nil
}

func (h *clientHandshake) retryRequest(m handshakeMessage, hello serverHello) ([]handshakeMessage, error) {
	if h.retried {
		return nil, errUnexpectedMessage
	}
	for id := range hello.extensions {
		if _, ok := h.hello.extensions[id]; !ok && id != extCookie {
			return nil, errUnsupportedExtension
		}
		if id != extSupportedVersions && id != extCookie && id != extKeyShare {
			return nil, errIllegalParameter
		}
	}
	changed := false
	if data, ok := hello.extensions[extCookie]; ok {
		if _, err := parseCookie(data); err != nil {
			return nil, err
		}
		h.hello.extensions[extCookie] = slices.Clone(data)
		changed = true
	}
	if data, ok := hello.extensions[extKeyShare]; ok {
		if len(data) != 2 {
			return nil, errDecode
		}
		group := binary.BigEndian.Uint16(data)
		if h.shares[group] != nil {
			return nil, errIllegalParameter
		}
		groups, err := parseList16(h.hello.extensions[extSupportedGroups])
		if err != nil {
			return nil, err
		}
		if !slices.Contains(groups, group) {
			return nil, errIllegalParameter
		}
		private, err := generateShare(group)
		if err != nil {
			return nil, err
		}
		share, err := encodeKeyShare(group, private.public)
		if err != nil {
			return nil, err
		}
		list := wireWriter{}
		list.vector16(share)
		h.hello.extensions[extKeyShare] = list.data
		h.shares = map[uint16]*keyShare{group: private}
		changed = true
	}
	if !changed {
		return nil, errIllegalParameter
	}
	h.retried = true
	h.retrySuite = hello.suite
	var err error
	h.retryHello, err = m.transcript()
	if err != nil {
		return nil, err
	}
	body, err := h.hello.marshal()
	if err != nil {
		return nil, err
	}
	response, err := h.message(msgClientHello, 0, body)
	if err != nil {
		return nil, err
	}
	return []handshakeMessage{response}, nil
}

func (h *clientHandshake) encryptedExtensions(m handshakeMessage) error {
	r := wireReader{data: m.body}
	data := r.vector16()
	if r.done() != nil {
		return errDecode
	}
	ext, err := parseExtensions(data, msgEncryptedExtensions)
	if err != nil {
		return err
	}
	for id, data := range ext {
		if _, ok := h.hello.extensions[id]; !ok {
			return errUnsupportedExtension
		}
		switch id {
		case extServerName:
			if len(data) != 0 {
				return errDecode
			}
		case extALPN:
			protocols, err := parseALPN(data)
			if err != nil {
				return err
			}
			if len(protocols) != 1 || !slices.Contains(h.config.NextProtos, protocols[0]) {
				return errIllegalParameter
			}
			h.state.NegotiatedProtocol = protocols[0]
		case extSupportedGroups:
			if _, err := parseList16(data); err != nil {
				return err
			}
		default:
			return errUnsupportedExtension
		}
	}
	return h.schedule.write(m)
}

func (h *clientHandshake) finalFlight() ([]handshakeMessage, error) {
	var err error
	h.clientApplication, h.serverApplication, err = h.schedule.applicationSecrets()
	if err != nil {
		return nil, err
	}
	var flight []handshakeMessage
	if h.requestedCertificate {
		cert, scheme, err := chooseCertificate(h.config, h.certificateSignatures, "", h.authorities, true)
		if err != nil {
			return nil, err
		}
		flight, err = h.certificateFlight(cert, scheme)
		if err != nil {
			return nil, err
		}
	}
	body, err := h.schedule.finished(h.schedule.clientHandshake)
	if err != nil {
		return nil, err
	}
	finished, err := h.message(msgFinished, 2, body)
	if err != nil {
		return nil, err
	}
	flight = append(flight, finished)
	if err := h.finish(); err != nil {
		return nil, err
	}
	return flight, nil
}
