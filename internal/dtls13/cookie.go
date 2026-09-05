package dtls13

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"slices"
	"time"
)

const cookieLifetime = time.Minute

// The listener's random key and authenticated timestamp bound cookie reuse.
type cookieKey [32]byte

func (k *cookieKey) mac(peer netip.AddrPort, data []byte) []byte {
	h := hmac.New(sha256.New, k[:])
	_, _ = h.Write([]byte("dtls13 retry cookie\x00"))
	_, _ = h.Write([]byte(peer.String()))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(data)
	return h.Sum(nil)
}

// Hash unchanged fields separately from the exact CH1 transcript. PSK identity
// hashes preserve allowed removals without copying tickets into the cookie.
func retryFingerprint(hello clientHello, groupRequested bool) ([]byte, error) {
	ext := make(extensions, len(hello.extensions))
	for id, data := range hello.extensions {
		if id != extCookie && id != 21 && id != extPreSharedKey && id != extEarlyData && (!groupRequested || id != extKeyShare) {
			ext[id] = data
		}
	}
	hello.extensions = ext
	wire, err := hello.marshal()
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(wire)
	return hash[:], nil
}

func pskIdentityHashes(data []byte) []byte {
	if data == nil {
		return nil
	}
	r := wireReader{data: data}
	identities := wireReader{data: r.vector16()}
	var hashes []byte
	for len(identities.data) != 0 && identities.err == nil {
		hash := sha256.Sum256(identities.vector16())
		identities.take(4)
		hashes = append(hashes, hash[:]...)
	}
	return hashes
}

func retryIdentitySubset(first, second []byte) bool {
	for len(second) != 0 {
		found := false
		for len(first) != 0 {
			match := bytes.Equal(first[:sha256.Size], second[:sha256.Size])
			first = first[sha256.Size:]
			if match {
				found = true
				break
			}
		}
		if !found {
			return false
		}
		second = second[sha256.Size:]
	}
	return true
}

func (k *cookieKey) issue(config *Config, peer netip.AddrPort, m handshakeMessage, hello clientHello, offer clientOffer, now time.Time) (handshakeMessage, error) {
	seconds := now.Unix()
	if seconds < 0 {
		return handshakeMessage{}, errIllegalParameter
	}
	var suiteID, group uint16
	for _, id := range config.CipherSuites {
		if slices.Contains(hello.suites, id) {
			suiteID = id
			break
		}
	}
	for _, id := range config.CurvePreferences {
		if slices.Contains(offer.groups, uint16(id)) {
			group = uint16(id)
			break
		}
	}
	if suiteID == 0 || group == 0 {
		return handshakeMessage{}, errHandshakeFailure
	}
	suite, err := suiteFor(suiteID)
	if err != nil {
		return handshakeMessage{}, err
	}
	first, err := m.transcript()
	if err != nil {
		return handshakeMessage{}, err
	}
	hash := suite.hash()
	_, _ = hash.Write(first)
	requested := offer.shares[group] == nil
	fingerprint, err := retryFingerprint(hello, requested)
	if err != nil {
		return handshakeMessage{}, err
	}
	w := wireWriter{}
	w.uint8(1)
	w.data = binary.BigEndian.AppendUint64(w.data, uint64(seconds))
	w.uint16(suiteID)
	w.uint16(group)
	flag := byte(0)
	if requested {
		flag = 1
	}
	w.uint8(flag)
	w.vector8(hash.Sum(nil))
	w.data = append(w.data, fingerprint...)
	w.vector16(pskIdentityHashes(hello.extensions[extPreSharedKey]))
	if w.err != nil {
		return handshakeMessage{}, w.err
	}
	w.data = append(w.data, k.mac(peer, w.data)...)
	body, err := retryHelloBody(suiteID, group, requested, w.data)
	return handshakeMessage{typ: msgServerHello, body: body}, err
}

func (k *cookieKey) verify(config *Config, peer netip.AddrPort, hello clientHello, offer clientOffer, now time.Time) (*serverHandshake, error) {
	seconds := now.Unix()
	if seconds < 0 {
		return nil, errIllegalParameter
	}
	cookie := offer.cookie
	if len(cookie) < sha256.Size || !hmac.Equal(cookie[len(cookie)-sha256.Size:], k.mac(peer, cookie[:len(cookie)-sha256.Size])) {
		return nil, errIllegalParameter
	}
	r := wireReader{data: cookie[:len(cookie)-sha256.Size]}
	version := r.uint8()
	timestamp := r.take(8)
	if r.err != nil {
		return nil, errIllegalParameter
	}
	issued := binary.BigEndian.Uint64(timestamp)
	suiteID, group, flag := r.uint16(), r.uint16(), r.uint8()
	firstHash, fingerprint, identities := r.vector8(), r.take(sha256.Size), r.vector16()
	if r.done() != nil || version != 1 || flag > 1 || len(identities)%sha256.Size != 0 ||
		issued > uint64(seconds) || uint64(seconds)-issued >= uint64(cookieLifetime/time.Second) {
		return nil, errIllegalParameter
	}
	suite, err := suiteFor(suiteID)
	if err != nil || len(firstHash) != suite.hash().Size() || !slices.Contains(config.CipherSuites, suiteID) || !slices.Contains(hello.suites, suiteID) {
		return nil, errIllegalParameter
	}
	if _, ok := hello.extensions[extEarlyData]; ok {
		return nil, errIllegalParameter
	}
	current, err := retryFingerprint(hello, flag == 1)
	if err != nil || !hmac.Equal(current, fingerprint) || !retryIdentitySubset(identities, pskIdentityHashes(hello.extensions[extPreSharedKey])) ||
		!slices.Contains(offer.groups, group) || offer.shares[group] == nil || flag == 1 && len(offer.shares) != 1 {
		return nil, errIllegalParameter
	}
	h, err := newServerHandshake(config)
	if err != nil {
		return nil, err
	}
	h.retried, h.groupRequested = true, flag == 1
	h.first, h.selectedSuite, h.selectedGroup = hello, suiteID, group
	h.cookie, h.firstHelloHash = bytes.Clone(cookie), bytes.Clone(firstHash)
	body, err := retryHelloBody(suiteID, group, h.groupRequested, cookie)
	if err != nil {
		return nil, err
	}
	m, err := h.message(msgServerHello, 0, body)
	if err != nil {
		return nil, err
	}
	h.retryHello, err = m.transcript()
	return h, err
}
