package dtls13

import (
	"bytes"
	"slices"
)

type clientOffer struct {
	groups     []uint16
	signatures []uint16
	shares     map[uint16][]byte
	serverName string
	protocols  []string
	cid        []byte
	cidOffered bool
	rrc        bool
	cookie     []byte
}

func parseClientOffer(hello clientHello) (clientOffer, error) {
	o := clientOffer{}
	for _, required := range []uint16{extSupportedVersions, extSupportedGroups, extKeyShare, extSignatureAlgorithms} {
		if _, ok := hello.extensions[required]; !ok {
			return o, errMissingExtension
		}
	}
	versions, err := parseVersions(hello.extensions[extSupportedVersions])
	if err != nil {
		return o, err
	}
	if !slices.Contains(versions, version13) {
		return o, errProtocolVersion
	}
	o.groups, err = parseList16(hello.extensions[extSupportedGroups])
	if err != nil {
		return o, err
	}
	o.signatures, err = parseList16(hello.extensions[extSignatureAlgorithms])
	if err != nil {
		return o, err
	}
	o.shares, err = parseClientShares(hello.extensions[extKeyShare], o.groups)
	if err != nil {
		return o, err
	}
	if data, ok := hello.extensions[extServerName]; ok {
		o.serverName, err = parseServerName(data)
		if err != nil {
			return o, err
		}
	}
	if data, ok := hello.extensions[extALPN]; ok {
		o.protocols, err = parseALPN(data)
		if err != nil {
			return o, err
		}
	}
	if data, ok := hello.extensions[extConnectionID]; ok {
		o.cid, err = parseConnectionID(data)
		if err != nil {
			return o, err
		}
		o.cidOffered = true
	}
	if data, ok := hello.extensions[extRRC]; ok {
		if len(data) != 0 {
			return o, errDecode
		}
		o.rrc = o.cidOffered
	}
	if data, ok := hello.extensions[extCookie]; ok {
		o.cookie, err = parseCookie(data)
		if err != nil {
			return o, err
		}
	}
	if data, ok := hello.extensions[extPreSharedKey]; ok {
		modes, ok := hello.extensions[extPSKModes]
		if !ok {
			return o, errMissingExtension
		}
		if err := validatePSKOffer(data, modes); err != nil {
			return o, err
		}
	}
	if data, ok := hello.extensions[extEarlyData]; ok {
		if len(data) != 0 {
			return o, errDecode
		}
		if _, ok := hello.extensions[extPreSharedKey]; !ok {
			return o, errIllegalParameter
		}
	}
	return o, nil
}

func validatePSKOffer(data, modes []byte) error {
	modeReader := wireReader{data: modes}
	modeList := modeReader.vector8()
	if modeReader.done() != nil || len(modeList) == 0 {
		return errDecode
	}
	r := wireReader{data: data}
	identities := wireReader{data: r.vector16()}
	binders := wireReader{data: r.vector16()}
	if r.done() != nil || len(identities.data) == 0 {
		return errDecode
	}
	count := 0
	for len(identities.data) != 0 && identities.err == nil {
		identity := identities.vector16()
		identities.take(4)
		if len(identity) == 0 || identities.err != nil {
			return errDecode
		}
		count++
	}
	for len(binders.data) != 0 && binders.err == nil {
		binder := binders.vector8()
		if len(binder) < 32 || binders.err != nil {
			return errDecode
		}
		count--
	}
	if identities.done() != nil || binders.done() != nil || count != 0 {
		return errDecode
	}
	return nil
}

func consistentRetry(first, second clientHello, groupRequested bool) bool {
	if first.random != second.random || !bytes.Equal(first.sessionID, second.sessionID) || !slices.Equal(first.suites, second.suites) {
		return false
	}
	if _, ok := second.extensions[extEarlyData]; ok {
		return false
	}
	if !retryPSKIdentities(first.extensions[extPreSharedKey], second.extensions[extPreSharedKey]) {
		return false
	}
	// Cookie, padding, PSK binders/ages, and a requested key share can change.
	ignored := func(id uint16) bool {
		return id == extCookie || id == 21 || id == extPreSharedKey || id == extEarlyData || groupRequested && id == extKeyShare
	}
	for id, data := range first.extensions {
		if !ignored(id) {
			other, ok := second.extensions[id]
			if !ok || !bytes.Equal(data, other) {
				return false
			}
		}
	}
	for id := range second.extensions {
		if !ignored(id) {
			if _, ok := first.extensions[id]; !ok {
				return false
			}
		}
	}
	return true
}

// A retry may remove incompatible PSKs, but cannot add or reorder identities.
func retryPSKIdentities(first, second []byte) bool {
	if second == nil {
		return true
	}
	a, b := wireReader{data: first}, wireReader{data: second}
	old, updated := wireReader{data: a.vector16()}, wireReader{data: b.vector16()}
	if a.err != nil || b.err != nil {
		return false
	}
	for len(updated.data) != 0 {
		identity := updated.vector16()
		updated.take(4)
		if updated.err != nil {
			return false
		}
		found := false
		for len(old.data) != 0 {
			candidate := old.vector16()
			old.take(4)
			if old.err != nil {
				return false
			}
			if bytes.Equal(candidate, identity) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func parseCertificateRequest(data []byte) ([]uint16, [][]byte, error) {
	r := wireReader{data: data}
	context := r.vector8()
	extData := r.vector16()
	if r.done() != nil {
		return nil, nil, errDecode
	}
	if len(context) != 0 {
		return nil, nil, errIllegalParameter
	}
	ext, err := parseExtensions(extData, msgCertificateRequest)
	if err != nil {
		return nil, nil, err
	}
	signatures, ok := ext[extSignatureAlgorithms]
	if !ok {
		return nil, nil, errMissingExtension
	}
	schemes, err := parseList16(signatures)
	if err != nil {
		return nil, nil, err
	}
	var authorities [][]byte
	if data, ok := ext[extCertificateAuthorities]; ok {
		reader := wireReader{data: data}
		list := wireReader{data: reader.vector16()}
		if reader.done() != nil || len(list.data) == 0 {
			return nil, nil, errDecode
		}
		for len(list.data) != 0 && list.err == nil {
			name := list.vector16()
			if len(name) == 0 || list.err != nil {
				return nil, nil, errDecode
			}
			authorities = append(authorities, name)
		}
	}
	return schemes, authorities, nil
}

func encodeCertificateRequest(authorities [][]byte) ([]byte, error) {
	signatures, err := encodeList16(signatureSchemes)
	if err != nil {
		return nil, err
	}
	ext := extensions{extSignatureAlgorithms: signatures}
	if len(authorities) != 0 {
		list := wireWriter{}
		for _, name := range authorities {
			if len(name) == 0 {
				return nil, errDecode
			}
			list.vector16(name)
			if list.err != nil || len(list.data) > 65533 {
				return nil, errHandshakeLimit
			}
		}
		ca := wireWriter{}
		ca.vector16(list.data)
		ext[extCertificateAuthorities] = ca.data
	}
	encoded, err := ext.marshal()
	if err != nil {
		return nil, err
	}
	w := wireWriter{}
	w.vector8(nil)
	w.vector16(encoded)
	return w.result()
}
