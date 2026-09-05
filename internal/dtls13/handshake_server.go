package dtls13

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"slices"
)

type serverHandshake struct {
	*handshakeState
	phase                          byte
	first                          clientHello
	firstHello, retryHello, cookie []byte
	retried                        bool
	selectedSuite, selectedGroup   uint16
	groupRequested                 bool
}

func newServerHandshake(config *Config) (*serverHandshake, error) {
	state, err := newHandshakeState(config, false)
	if err != nil {
		return nil, err
	}
	return &serverHandshake{handshakeState: state, phase: msgClientHello}, nil
}

func (h *serverHandshake) handle(m handshakeMessage) ([]handshakeMessage, error) {
	if h.complete {
		return nil, errUnexpectedMessage
	}
	if h.phase == msgClientHello {
		if m.typ != msgClientHello || m.epoch != 0 {
			return nil, errUnexpectedMessage
		}
		return h.clientHello(m)
	}
	if m.epoch != 2 {
		return nil, errUnexpectedMessage
	}
	switch h.phase {
	case msgCertificate:
		if m.typ != msgCertificate {
			return nil, errUnexpectedMessage
		}
		if err := h.peerCertificate(m); err != nil {
			return nil, err
		}
		h.phase = msgCertificateVerify
		if len(h.state.PeerCertificates) == 0 {
			h.phase = msgFinished
		}
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
		if err := h.finish(); err != nil {
			return nil, err
		}
	default:
		return nil, errUnexpectedMessage
	}
	return nil, nil
}

func (h *serverHandshake) clientHello(m handshakeMessage) ([]handshakeMessage, error) {
	hello, err := parseClientHello(m.body)
	if err != nil {
		return nil, err
	}
	offer, err := parseClientOffer(hello)
	if err != nil {
		return nil, err
	}
	if !h.retried {
		if len(offer.cookie) != 0 {
			return nil, errIllegalParameter
		}
		for _, suite := range h.config.CipherSuites {
			if slices.Contains(hello.suites, suite) {
				h.selectedSuite = suite
				break
			}
		}
		for _, group := range h.config.CurvePreferences {
			if slices.Contains(offer.groups, uint16(group)) {
				h.selectedGroup = uint16(group)
				break
			}
		}
		if h.selectedSuite == 0 || h.selectedGroup == 0 {
			return nil, errHandshakeFailure
		}
		h.first = hello
		h.firstHello, err = m.transcript()
		if err != nil {
			return nil, err
		}
		h.groupRequested = offer.shares[h.selectedGroup] == nil
		return h.retryRequest()
	}
	if !hmac.Equal(offer.cookie, h.cookie) || !consistentRetry(h.first, hello, h.groupRequested) {
		return nil, errIllegalParameter
	}
	if h.groupRequested && len(offer.shares) != 1 {
		return nil, errIllegalParameter
	}
	if offer.shares[h.selectedGroup] == nil {
		return nil, errIllegalParameter
	}
	return h.serverFlight(m, offer)
}

func (h *serverHandshake) retryRequest() ([]handshakeMessage, error) {
	h.cookie = make([]byte, 32)
	if _, err := rand.Read(h.cookie); err != nil {
		return nil, err
	}
	cookie := wireWriter{}
	cookie.vector16(h.cookie)
	ext := extensions{extSupportedVersions: {0xfe, 0xfc}, extCookie: cookie.data}
	if h.groupRequested {
		group := wireWriter{}
		group.uint16(h.selectedGroup)
		ext[extKeyShare] = group.data
	}
	hello := serverHello{random: retryRandom, suite: h.selectedSuite, extensions: ext}
	body, err := hello.marshal()
	if err != nil {
		return nil, err
	}
	m, err := h.message(msgServerHello, 0, body)
	if err != nil {
		return nil, err
	}
	h.retryHello, err = m.transcript()
	if err != nil {
		return nil, err
	}
	h.retried = true
	return []handshakeMessage{m}, nil
}

func (h *serverHandshake) serverFlight(clientMessage handshakeMessage, offer clientOffer) ([]handshakeMessage, error) {
	private, err := generateShare(h.selectedGroup)
	if err != nil {
		return nil, err
	}
	shared, err := computeShared(private, offer.shares[h.selectedGroup])
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	share, err := encodeKeyShare(h.selectedGroup, private.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	hello := serverHello{suite: h.selectedSuite, extensions: extensions{extSupportedVersions: {0xfe, 0xfc}, extKeyShare: share}}
	if _, err := rand.Read(hello.random[:]); err != nil {
		return nil, err
	}
	if offer.cidOffered && len(h.localCID) != 0 {
		cid := wireWriter{}
		cid.vector8(h.localCID)
		hello.extensions[extConnectionID] = cid.data
		h.peerCID = slices.Clone(offer.cid)
		h.cidNegotiated = true
		if offer.rrc {
			hello.extensions[extRRC] = nil
			h.rrc = true
		}
	}
	cert, scheme, err := chooseCertificate(h.config, offer.signatures, offer.serverName, nil, false)
	if err != nil {
		return nil, err
	}
	h.state.ServerName = offer.serverName
	h.state.CipherSuite = h.selectedSuite
	body, err := hello.marshal()
	if err != nil {
		return nil, err
	}
	serverMessage, err := h.message(msgServerHello, 0, body)
	if err != nil {
		return nil, err
	}
	second, err := clientMessage.transcript()
	if err != nil {
		return nil, err
	}
	transcript, err := retryTranscript(h.selectedSuite, h.firstHello, h.retryHello, second)
	if err != nil {
		return nil, err
	}
	server, err := serverMessage.transcript()
	if err != nil {
		return nil, err
	}
	transcript = append(transcript, server...)
	h.schedule, err = newKeySchedule(h.selectedSuite, shared, transcript)
	if err != nil {
		return nil, err
	}
	flight := []handshakeMessage{serverMessage}
	ext := make(extensions)
	if offer.serverName != "" {
		ext[extServerName] = nil
	}
	if len(offer.protocols) != 0 && len(h.config.NextProtos) != 0 {
		for _, protocol := range h.config.NextProtos {
			if slices.Contains(offer.protocols, protocol) {
				h.state.NegotiatedProtocol = protocol
				break
			}
		}
		if h.state.NegotiatedProtocol == "" {
			return nil, errNoApplicationProtocol
		}
		alpn, err := encodeALPN([]string{h.state.NegotiatedProtocol})
		if err != nil {
			return nil, err
		}
		ext[extALPN] = alpn
	}
	encoded, err := ext.marshal()
	if err != nil {
		return nil, err
	}
	w := wireWriter{}
	w.vector16(encoded)
	encrypted, err := h.message(msgEncryptedExtensions, 2, w.data)
	if err != nil {
		return nil, err
	}
	flight = append(flight, encrypted)
	if h.config.ClientAuth != tls.NoClientCert {
		var authorities [][]byte
		if h.config.ClientCAs != nil {
			authorities = h.config.ClientCAs.Subjects() //nolint:staticcheck // Selection hints only; verification uses the complete pool.
		}
		request, err := encodeCertificateRequest(authorities)
		if err != nil {
			return nil, err
		}
		certificateRequest, err := h.message(msgCertificateRequest, 2, request)
		if err != nil {
			return nil, err
		}
		flight = append(flight, certificateRequest)
	}
	certificate, err := h.certificateFlight(cert, scheme)
	if err != nil {
		return nil, err
	}
	flight = append(flight, certificate...)
	finished, err := h.schedule.finished(h.schedule.serverHandshake)
	if err != nil {
		return nil, err
	}
	finishMessage, err := h.message(msgFinished, 2, finished)
	if err != nil {
		return nil, err
	}
	flight = append(flight, finishMessage)
	h.clientApplication, h.serverApplication, err = h.schedule.applicationSecrets()
	if err != nil {
		return nil, err
	}
	h.phase = msgFinished
	if h.config.ClientAuth != tls.NoClientCert {
		h.phase = msgCertificate
	}
	return flight, nil
}
