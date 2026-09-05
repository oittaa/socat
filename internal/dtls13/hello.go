package dtls13

import (
	"bytes"
	"encoding/binary"
	"slices"
)

const (
	version13              = uint16(0xfefc)
	legacyVersion          = uint16(0xfefd)
	msgClientHello         = byte(1)
	msgServerHello         = byte(2)
	msgNewSessionTicket    = byte(4)
	msgEncryptedExtensions = byte(8)
	msgRequestConnectionID = byte(9)
	msgNewConnectionID     = byte(10)
	msgCertificate         = byte(11)
	msgCertificateRequest  = byte(13)
	msgCertificateVerify   = byte(15)
	msgFinished            = byte(20)
	msgKeyUpdate           = byte(24)
	msgMessageHash         = byte(254)

	extServerName              = uint16(0)
	extSupportedGroups         = uint16(10)
	extSignatureAlgorithms     = uint16(13)
	extALPN                    = uint16(16)
	extPreSharedKey            = uint16(41)
	extEarlyData               = uint16(42)
	extSupportedVersions       = uint16(43)
	extCookie                  = uint16(44)
	extPSKModes                = uint16(45)
	extCertificateAuthorities  = uint16(47)
	extSignatureAlgorithmsCert = uint16(50)
	extKeyShare                = uint16(51)
	extConnectionID            = uint16(54)
	extRRC                     = uint16(61)
)

var retryRandom = [32]byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

type extensions map[uint16][]byte

func parseExtensions(data []byte, messageType byte) (extensions, error) {
	r := wireReader{data: data}
	out := make(extensions)
	for len(r.data) != 0 && r.err == nil {
		id := r.uint16()
		body := r.vector16()
		if _, exists := out[id]; exists {
			return nil, errDecode
		}
		out[id] = body
		if messageType == msgClientHello && id == extPreSharedKey && len(r.data) != 0 {
			return nil, errDecode
		}
	}
	return out, r.done()
}

func (e extensions) marshal() ([]byte, error) {
	keys := make([]uint16, 0, len(e))
	for id := range e {
		if id != extPreSharedKey {
			keys = append(keys, id)
		}
	}
	slices.Sort(keys)
	if _, ok := e[extPreSharedKey]; ok {
		keys = append(keys, extPreSharedKey)
	}
	w := wireWriter{}
	for _, id := range keys {
		w.uint16(id)
		w.vector16(e[id])
	}
	if w.err != nil {
		return nil, w.err
	}
	if len(w.data) > 65535 {
		return nil, errDecode
	}
	return w.result()
}

type clientHello struct {
	random     [32]byte
	sessionID  []byte
	suites     []uint16
	extensions extensions
}

func parseClientHello(data []byte) (clientHello, error) {
	r := wireReader{data: data}
	version := r.uint16()
	h := clientHello{}
	copy(h.random[:], r.take(32))
	h.sessionID = r.vector8()
	cookie := r.vector8()
	suites := r.vector16()
	compression := r.vector8()
	ext := r.vector16()
	if r.done() != nil || len(h.sessionID) > 32 || len(suites) < 2 || len(suites)%2 != 0 || len(ext) < 8 {
		return clientHello{}, errDecode
	}
	if version != legacyVersion {
		return clientHello{}, errProtocolVersion
	}
	if len(cookie) != 0 || !bytes.Equal(compression, []byte{0}) {
		return clientHello{}, errIllegalParameter
	}
	for len(suites) != 0 {
		h.suites = append(h.suites, binary.BigEndian.Uint16(suites))
		suites = suites[2:]
	}
	var err error
	h.extensions, err = parseExtensions(ext, msgClientHello)
	return h, err
}

func (h clientHello) marshal() ([]byte, error) {
	if len(h.sessionID) > 32 || len(h.suites) == 0 || len(h.suites) > 32767 {
		return nil, errDecode
	}
	ext, err := h.extensions.marshal()
	if err != nil {
		return nil, err
	}
	if len(ext) < 8 {
		return nil, errDecode
	}
	w := wireWriter{}
	w.uint16(legacyVersion)
	w.data = append(w.data, h.random[:]...)
	w.vector8(h.sessionID)
	w.vector8(nil)
	suites := wireWriter{}
	for _, suite := range h.suites {
		suites.uint16(suite)
	}
	w.vector16(suites.data)
	w.vector8([]byte{0})
	w.vector16(ext)
	return w.result()
}

type serverHello struct {
	random     [32]byte
	sessionID  []byte
	suite      uint16
	extensions extensions
}

func parseServerHello(data []byte) (serverHello, error) {
	r := wireReader{data: data}
	version := r.uint16()
	h := serverHello{}
	copy(h.random[:], r.take(32))
	h.sessionID = r.vector8()
	h.suite = r.uint16()
	compression := r.uint8()
	ext := r.vector16()
	if r.done() != nil || len(h.sessionID) > 32 {
		return serverHello{}, errDecode
	}
	if version != legacyVersion {
		return serverHello{}, errProtocolVersion
	}
	if compression != 0 {
		return serverHello{}, errIllegalParameter
	}
	var err error
	h.extensions, err = parseExtensions(ext, msgServerHello)
	return h, err
}

func (h serverHello) marshal() ([]byte, error) {
	if len(h.sessionID) > 32 {
		return nil, errDecode
	}
	ext, err := h.extensions.marshal()
	if err != nil {
		return nil, err
	}
	w := wireWriter{}
	w.uint16(legacyVersion)
	w.data = append(w.data, h.random[:]...)
	w.vector8(h.sessionID)
	w.uint16(h.suite)
	w.uint8(0)
	w.vector16(ext)
	return w.result()
}

func (h serverHello) retry() bool { return h.random == retryRandom }

func uint16List(data []byte) ([]uint16, error) {
	if len(data) == 0 || len(data)%2 != 0 {
		return nil, errDecode
	}
	out := make([]uint16, 0, len(data)/2)
	for len(data) != 0 {
		out = append(out, binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	return out, nil
}
