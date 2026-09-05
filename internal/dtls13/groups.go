package dtls13

import (
	"crypto"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/tls"
)

const (
	groupP256   = uint16(tls.CurveP256)
	groupX25519 = uint16(tls.X25519)
)

// The order follows Go's TLS 1.3 preferences. Hybrid formats are RFC 10024.
var keyExchangeGroups = []keyExchangeGroup{
	{tls.X25519MLKEM768, ecdh.X25519(), 768, true},
	{tls.SecP256r1MLKEM768, ecdh.P256(), 768, false},
	{tls.SecP384r1MLKEM1024, ecdh.P384(), 1024, false},
	{tls.X25519, ecdh.X25519(), 0, false},
	{tls.CurveP256, ecdh.P256(), 0, false},
	{tls.CurveP384, ecdh.P384(), 0, false},
	{tls.CurveP521, ecdh.P521(), 0, false},
}

type keyExchangeGroup struct {
	id       tls.CurveID
	curve    ecdh.Curve
	kem      int
	kemFirst bool
}

func groupFor(id uint16) (keyExchangeGroup, error) {
	for _, group := range keyExchangeGroups {
		if uint16(group.id) == id {
			return group, nil
		}
	}
	return keyExchangeGroup{}, errIllegalParameter
}

func defaultGroups() []tls.CurveID {
	groups := make([]tls.CurveID, 0, len(keyExchangeGroups))
	for _, group := range keyExchangeGroups {
		groups = append(groups, group.id)
	}
	return groups
}

type keyShare struct {
	group  keyExchangeGroup
	ecdh   *ecdh.PrivateKey
	kem    crypto.Decapsulator
	public []byte
}

func generateShare(id uint16) (*keyShare, error) {
	group, err := groupFor(id)
	if err != nil {
		return nil, err
	}
	private, err := group.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	s := &keyShare{group: group, ecdh: private, public: private.PublicKey().Bytes()}
	switch group.kem {
	case 768:
		s.kem, err = mlkem.GenerateKey768()
	case 1024:
		s.kem, err = mlkem.GenerateKey1024()
	}
	if err != nil {
		return nil, err
	}
	if s.kem != nil {
		s.public = group.combine(s.public, s.kem.Encapsulator().Bytes())
	}
	return s, nil
}

func (g keyExchangeGroup) combine(ec, kem []byte) []byte {
	if g.kemFirst {
		return append(kem, ec...)
	}
	return append(ec, kem...)
}

func (g keyExchangeGroup) split(wire []byte, server bool) (ec, kem []byte, err error) {
	ecSize := 0
	switch g.curve {
	case ecdh.X25519():
		ecSize = 32
	case ecdh.P256():
		ecSize = 65
	case ecdh.P384():
		ecSize = 97
	case ecdh.P521():
		ecSize = 133
	}
	kemSize := 0
	switch g.kem {
	case 768:
		kemSize = mlkem.EncapsulationKeySize768
		if server {
			kemSize = mlkem.CiphertextSize768
		}
	case 1024:
		kemSize = mlkem.EncapsulationKeySize1024
		if server {
			kemSize = mlkem.CiphertextSize1024
		}
	}
	if len(wire) != ecSize+kemSize {
		return nil, nil, errIllegalParameter
	}
	if g.kemFirst {
		return wire[kemSize:], wire[:kemSize], nil
	}
	return wire[:ecSize], wire[ecSize:], nil
}

func (s *keyShare) shared(peer []byte) ([]byte, error) {
	ec, ciphertext, err := s.group.split(peer, true)
	if err != nil {
		return nil, err
	}
	secret, err := computeShared(s.ecdh, ec)
	if err != nil {
		return nil, err
	}
	if s.kem == nil {
		return secret, nil
	}
	defer clear(secret)
	kemSecret, err := s.kem.Decapsulate(ciphertext)
	if err != nil {
		return nil, errInternal
	}
	defer clear(kemSecret)
	return s.group.combine(append([]byte(nil), secret...), append([]byte(nil), kemSecret...)), nil
}

func serverShare(id uint16, peer []byte) (public, shared []byte, err error) {
	g, err := groupFor(id)
	if err != nil {
		return nil, nil, err
	}
	ec, encapsulationKey, err := g.split(peer, false)
	if err != nil {
		return nil, nil, err
	}
	private, err := g.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	secret, err := computeShared(private, ec)
	if err != nil {
		return nil, nil, err
	}
	public = private.PublicKey().Bytes()
	if g.kem == 0 {
		return public, secret, nil
	}
	defer clear(secret)
	var encapsulator crypto.Encapsulator
	switch g.kem {
	case 768:
		encapsulator, err = mlkem.NewEncapsulationKey768(encapsulationKey)
	case 1024:
		encapsulator, err = mlkem.NewEncapsulationKey1024(encapsulationKey)
	}
	if err != nil {
		return nil, nil, errIllegalParameter
	}
	kemSecret, ciphertext := encapsulator.Encapsulate()
	defer clear(kemSecret)
	return g.combine(public, ciphertext), g.combine(append([]byte(nil), secret...), append([]byte(nil), kemSecret...)), nil
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
