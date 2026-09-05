package dtls13

import (
	"crypto/hkdf"
	"crypto/hmac"
	"hash"
)

type keySchedule struct {
	suite           cipherSuite
	transcript      hash.Hash
	master          []byte
	clientHandshake []byte
	serverHandshake []byte
}

func newKeySchedule(id uint16, shared, helloTranscript []byte) (*keySchedule, error) {
	suite, err := suiteFor(id)
	if err != nil {
		return nil, err
	}
	if len(shared) == 0 {
		return nil, errKeyMaterial
	}
	zeros := make([]byte, suite.hash().Size())
	early, err := hkdf.Extract(suite.hash, zeros, zeros)
	if err != nil {
		return nil, err
	}
	derived, err := expandLabel(suite.hash, early, "derived", suite.hash().Sum(nil), len(zeros))
	if err != nil {
		return nil, err
	}
	handshake, err := hkdf.Extract(suite.hash, shared, derived)
	if err != nil {
		return nil, err
	}
	s := &keySchedule{suite: suite, transcript: suite.hash()}
	_, _ = s.transcript.Write(helloTranscript)
	s.clientHandshake, err = s.derive(handshake, "c hs traffic")
	if err != nil {
		return nil, err
	}
	s.serverHandshake, err = s.derive(handshake, "s hs traffic")
	if err != nil {
		return nil, err
	}
	derived, err = expandLabel(suite.hash, handshake, "derived", suite.hash().Sum(nil), len(zeros))
	if err != nil {
		return nil, err
	}
	s.master, err = hkdf.Extract(suite.hash, zeros, derived)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *keySchedule) derive(secret []byte, label string) ([]byte, error) {
	return expandLabel(s.suite.hash, secret, label, s.transcript.Sum(nil), s.transcript.Size())
}

func (s *keySchedule) write(m handshakeMessage) error {
	wire, err := m.transcript()
	if err != nil {
		return err
	}
	_, _ = s.transcript.Write(wire)
	return nil
}

func (s *keySchedule) finished(secret []byte) ([]byte, error) {
	if len(secret) != s.transcript.Size() {
		return nil, errKeyMaterial
	}
	key, err := expandLabel(s.suite.hash, secret, "finished", nil, s.transcript.Size())
	if err != nil {
		return nil, err
	}
	h := hmac.New(s.suite.hash, key)
	_, _ = h.Write(s.transcript.Sum(nil))
	return h.Sum(nil), nil
}

func (s *keySchedule) applicationSecrets() (client, server []byte, err error) {
	client, err = s.derive(s.master, "c ap traffic")
	if err != nil {
		return nil, nil, err
	}
	server, err = s.derive(s.master, "s ap traffic")
	return client, server, err
}

func nextTrafficSecret(id uint16, secret []byte) ([]byte, error) {
	suite, err := suiteFor(id)
	if err != nil {
		return nil, err
	}
	if len(secret) != suite.hash().Size() {
		return nil, errKeyMaterial
	}
	return expandLabel(suite.hash, secret, "traffic upd", nil, suite.hash().Size())
}

func retryTranscript(id uint16, firstClientHello, retry, secondClientHello []byte) ([]byte, error) {
	suite, err := suiteFor(id)
	if err != nil {
		return nil, err
	}
	h := suite.hash()
	_, _ = h.Write(firstClientHello)
	w := wireWriter{}
	w.uint8(msgMessageHash)
	w.vector24(h.Sum(nil))
	w.data = append(w.data, retry...)
	w.data = append(w.data, secondClientHello...)
	return w.result()
}
