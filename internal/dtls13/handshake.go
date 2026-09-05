package dtls13

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
)

type handshakeState struct {
	config                               *Config
	client                               bool
	sequence                             uint32
	schedule                             *keySchedule
	state                                tls.ConnectionState
	localCID, peerCID                    []byte
	cidNegotiated, rrc                   bool
	clientApplication, serverApplication []byte
	complete                             bool
}

func newHandshakeState(config *Config, client bool) (*handshakeState, error) {
	prepared, err := prepareConfig(config, !client)
	if err != nil {
		return nil, err
	}
	return preparedHandshakeState(prepared, client)
}

func preparedHandshakeState(prepared *Config, client bool) (*handshakeState, error) {
	h := &handshakeState{config: prepared, client: client, state: tls.ConnectionState{Version: version13, ServerName: prepared.ServerName}}
	if prepared.ConnectionIDLength != 0 {
		h.localCID = make([]byte, prepared.ConnectionIDLength)
		if _, err := rand.Read(h.localCID); err != nil {
			return nil, err
		}
	}
	return h, nil
}

func (h *handshakeState) message(typ byte, epoch uint64, body []byte) (handshakeMessage, error) {
	if h.sequence > 65535 {
		return handshakeMessage{}, errSequence
	}
	m := handshakeMessage{typ: typ, sequence: uint16(h.sequence), epoch: epoch, body: body}
	if h.schedule != nil && !h.complete {
		if err := h.schedule.write(m); err != nil {
			return handshakeMessage{}, err
		}
	}
	h.sequence++
	return m, nil
}

func (h *handshakeState) peerCertificate(m handshakeMessage) error {
	raw, err := parseCertificate(m.body, nil)
	if err != nil {
		return err
	}
	h.state.PeerCertificates, h.state.VerifiedChains, err = verifyPeer(h.config, raw, h.client)
	if err != nil {
		return err
	}
	return h.schedule.write(m)
}

func (h *handshakeState) peerCertificateVerify(m handshakeMessage, offered []uint16) error {
	if len(h.state.PeerCertificates) == 0 {
		return errUnexpectedMessage
	}
	if err := verifyCertificateVerify(h.state.PeerCertificates[0].PublicKey, offered, m.body, h.schedule.transcript.Sum(nil), h.client); err != nil {
		return err
	}
	return h.schedule.write(m)
}

func (h *handshakeState) peerFinished(m handshakeMessage) error {
	secret := h.schedule.clientHandshake
	if h.client {
		secret = h.schedule.serverHandshake
	}
	want, err := h.schedule.finished(secret)
	if err != nil {
		return err
	}
	if !hmac.Equal(want, m.body) {
		return errDecrypt
	}
	return h.schedule.write(m)
}

func (h *handshakeState) finish() error {
	h.state.HandshakeComplete = true
	if h.config.VerifyConnection != nil {
		if err := h.config.VerifyConnection(h.state); err != nil {
			h.state.HandshakeComplete = false
			return err
		}
	}
	h.complete = true
	return nil
}

func (h *handshakeState) certificateFlight(cert *tls.Certificate, scheme uint16) ([]handshakeMessage, error) {
	var chain [][]byte
	if cert != nil {
		chain = cert.Certificate
	}
	body, err := encodeCertificate(chain, nil)
	if err != nil {
		return nil, err
	}
	certificate, err := h.message(msgCertificate, 2, body)
	if err != nil {
		return nil, err
	}
	flight := []handshakeMessage{certificate}
	if cert != nil {
		signer, ok := cert.PrivateKey.(crypto.Signer)
		if !ok {
			return nil, errSignature
		}
		body, err := signCertificateVerify(signer, scheme, h.schedule.transcript.Sum(nil), !h.client)
		if err != nil {
			return nil, err
		}
		verify, err := h.message(msgCertificateVerify, 2, body)
		if err != nil {
			return nil, err
		}
		flight = append(flight, verify)
	}
	return flight, nil
}

func chooseCertificate(config *Config, signatures []uint16, serverName string, authorities [][]byte, client bool) (*tls.Certificate, uint16, error) {
	var fallback *tls.Certificate
	var fallbackScheme uint16
	for i := range config.Certificates {
		cert := &config.Certificates[i]
		signer, ok := cert.PrivateKey.(crypto.Signer)
		if !ok {
			continue
		}
		scheme, err := selectSignature(signer.Public(), signatures)
		if err != nil {
			continue
		}
		if client {
			request := &tls.CertificateRequestInfo{AcceptableCAs: authorities, Version: tls.VersionTLS13}
			for _, sig := range signatures {
				request.SignatureSchemes = append(request.SignatureSchemes, tls.SignatureScheme(sig))
			}
			if err := request.SupportsCertificate(cert); err != nil {
				continue
			}
			return cert, scheme, nil
		}
		if fallback == nil {
			fallback, fallbackScheme = cert, scheme
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err == nil && (serverName == "" || leaf.VerifyHostname(serverName) == nil) {
			return cert, scheme, nil
		}
	}
	if fallback != nil {
		return fallback, fallbackScheme, nil
	}
	if client {
		return nil, 0, nil
	}
	return nil, 0, errHandshakeFailure
}
