package dtls13

import "slices"

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
