package dtls13

import (
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"strings"
)

const (
	groupP256   = uint16(23)
	groupX25519 = uint16(29)
)

func groupCurve(group uint16) (ecdh.Curve, error) {
	switch group {
	case groupP256:
		return ecdh.P256(), nil
	case groupX25519:
		return ecdh.X25519(), nil
	default:
		return nil, errIllegalParameter
	}
}

func generateShare(group uint16) (*ecdh.PrivateKey, error) {
	curve, err := groupCurve(group)
	if err != nil {
		return nil, err
	}
	return curve.GenerateKey(rand.Reader)
}

func computeShared(private *ecdh.PrivateKey, peer []byte) ([]byte, error) {
	if private == nil {
		return nil, errKeyMaterial
	}
	public, err := private.Curve().NewPublicKey(peer)
	if err != nil {
		return nil, errIllegalParameter
	}
	secret, err := private.ECDH(public)
	if err != nil {
		return nil, errIllegalParameter
	}
	return secret, nil
}

func encodeList16(values []uint16) ([]byte, error) {
	if len(values) == 0 || len(values) > 32767 {
		return nil, errDecode
	}
	list := wireWriter{}
	for _, v := range values {
		list.uint16(v)
	}
	w := wireWriter{}
	w.vector16(list.data)
	return w.result()
}

func parseList16(data []byte) ([]uint16, error) {
	r := wireReader{data: data}
	list := r.vector16()
	if r.done() != nil {
		return nil, errDecode
	}
	return uint16List(list)
}

func parseVersions(data []byte) ([]uint16, error) {
	r := wireReader{data: data}
	list := r.vector8()
	if r.done() != nil {
		return nil, errDecode
	}
	return uint16List(list)
}

func encodeKeyShare(group uint16, public []byte) ([]byte, error) {
	if len(public) == 0 {
		return nil, errIllegalParameter
	}
	w := wireWriter{}
	w.uint16(group)
	w.vector16(public)
	return w.result()
}

func parseClientShares(data []byte, groups []uint16) (map[uint16][]byte, error) {
	r := wireReader{data: data}
	list := wireReader{data: r.vector16()}
	if r.done() != nil {
		return nil, errDecode
	}
	out := make(map[uint16][]byte)
	allowed := make(map[uint16]bool, len(groups))
	for _, group := range groups {
		allowed[group] = true
	}
	for len(list.data) != 0 && list.err == nil {
		group := list.uint16()
		public := list.vector16()
		if list.err != nil || len(public) == 0 {
			return nil, errDecode
		}
		if _, ok := out[group]; ok {
			return nil, errIllegalParameter
		}
		if !allowed[group] {
			return nil, errIllegalParameter
		}
		out[group] = public
	}
	return out, list.done()
}

func parseServerShare(data []byte) (uint16, []byte, error) {
	r := wireReader{data: data}
	group := r.uint16()
	public := r.vector16()
	if r.done() != nil || len(public) == 0 {
		return 0, nil, errDecode
	}
	return group, public, nil
}

func encodeServerName(name string) ([]byte, error) {
	if name == "" || strings.ContainsAny(name, "\x00[]:") || strings.HasSuffix(name, ".") || net.ParseIP(name) != nil {
		return nil, errIllegalParameter
	}
	entry := wireWriter{}
	entry.uint8(0)
	entry.vector16([]byte(name))
	if entry.err != nil {
		return nil, entry.err
	}
	w := wireWriter{}
	w.vector16(entry.data)
	return w.result()
}

func parseServerName(data []byte) (string, error) {
	r := wireReader{data: data}
	list := wireReader{data: r.vector16()}
	if r.done() != nil || len(list.data) == 0 {
		return "", errDecode
	}
	name := ""
	for len(list.data) != 0 && list.err == nil {
		kind := list.uint8()
		value := list.vector16()
		if list.err != nil || len(value) == 0 {
			return "", errDecode
		}
		if kind != 0 || name != "" {
			return "", errIllegalParameter
		}
		name = string(value)
		if _, err := encodeServerName(name); err != nil {
			return "", err
		}
	}
	return name, list.done()
}

func encodeALPN(protocols []string) ([]byte, error) {
	if len(protocols) == 0 {
		return nil, errIllegalParameter
	}
	list := wireWriter{}
	for _, protocol := range protocols {
		if protocol == "" {
			return nil, errIllegalParameter
		}
		list.vector8([]byte(protocol))
		if len(list.data) > 65535 || list.err != nil {
			return nil, errDecode
		}
	}
	w := wireWriter{}
	w.vector16(list.data)
	return w.result()
}

func parseALPN(data []byte) ([]string, error) {
	r := wireReader{data: data}
	list := wireReader{data: r.vector16()}
	if r.done() != nil || len(list.data) == 0 {
		return nil, errDecode
	}
	var protocols []string
	for len(list.data) != 0 && list.err == nil {
		protocol := list.vector8()
		if len(protocol) == 0 {
			return nil, errDecode
		}
		protocols = append(protocols, string(protocol))
	}
	return protocols, list.done()
}

func parseCookie(data []byte) ([]byte, error) {
	r := wireReader{data: data}
	cookie := r.vector16()
	if r.done() != nil || len(cookie) == 0 {
		return nil, errDecode
	}
	return cookie, nil
}

func parseConnectionID(data []byte) ([]byte, error) {
	r := wireReader{data: data}
	cid := r.vector8()
	return cid, r.done()
}
