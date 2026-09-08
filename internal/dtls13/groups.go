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

type kemKind uint16

const (
	kemNone      kemKind = 0
	kemMLKEM768  kemKind = 768
	kemMLKEM1024 kemKind = 1024
)

// shareOrigin selects the hybrid component on the wire: a client share carries
// an ML-KEM encapsulation key; a server share carries a ciphertext.
type shareOrigin uint8

const (
	shareFromClient shareOrigin = iota
	shareFromServer
)

// The order follows Go's TLS 1.3 preferences. Hybrid formats are RFC 10024.
var keyExchangeGroups = []keyExchangeGroup{
	{id: tls.X25519MLKEM768, curve: ecdh.X25519(), kem: kemMLKEM768, kemFirst: true},
	{id: tls.SecP256r1MLKEM768, curve: ecdh.P256(), kem: kemMLKEM768, kemFirst: false},
	{id: tls.SecP384r1MLKEM1024, curve: ecdh.P384(), kem: kemMLKEM1024, kemFirst: false},
	{id: tls.X25519, curve: ecdh.X25519(), kem: kemNone, kemFirst: false},
	{id: tls.CurveP256, curve: ecdh.P256(), kem: kemNone, kemFirst: false},
	{id: tls.CurveP384, curve: ecdh.P384(), kem: kemNone, kemFirst: false},
	{id: tls.CurveP521, curve: ecdh.P521(), kem: kemNone, kemFirst: false},
}

type keyExchangeGroup struct {
	id       tls.CurveID
	curve    ecdh.Curve
	kem      kemKind
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
	case kemNone: // ECDH-only public key.
	case kemMLKEM768:
		s.kem, err = mlkem.GenerateKey768()
	case kemMLKEM1024:
		s.kem, err = mlkem.GenerateKey1024()
	default:
		return nil, errIllegalParameter
	}
	if err != nil {
		return nil, err
	}
	if group.kem != kemNone {
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

func (g keyExchangeGroup) split(wire []byte, from shareOrigin) (ec, kem []byte, err error) {
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
	default:
		return nil, nil, errIllegalParameter
	}
	kemSize := 0
	switch g.kem {
	case kemNone: // ECDH-only share; kemSize stays 0.
	case kemMLKEM768:
		kemSize = mlkem.EncapsulationKeySize768
		if from == shareFromServer {
			kemSize = mlkem.CiphertextSize768
		}
	case kemMLKEM1024:
		kemSize = mlkem.EncapsulationKeySize1024
		if from == shareFromServer {
			kemSize = mlkem.CiphertextSize1024
		}
	default:
		return nil, nil, errIllegalParameter
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
	ec, ciphertext, err := s.group.split(peer, shareFromServer)
	if err != nil {
		return nil, err
	}
	secret, err := computeShared(s.ecdh, ec)
	if err != nil {
		return nil, err
	}
	switch s.group.kem {
	case kemNone:
		return secret, nil
	case kemMLKEM768, kemMLKEM1024:
		if s.kem == nil {
			return nil, errKeyMaterial
		}
		defer clear(secret)
		kemSecret, err := s.kem.Decapsulate(ciphertext)
		if err != nil {
			return nil, errInternal
		}
		defer clear(kemSecret)
		return s.group.combine(append([]byte(nil), secret...), append([]byte(nil), kemSecret...)), nil
	default:
		return nil, errIllegalParameter
	}
}

func serverShare(id uint16, peer []byte) (public, shared []byte, err error) {
	g, err := groupFor(id)
	if err != nil {
		return nil, nil, err
	}
	ec, encapsulationKey, err := g.split(peer, shareFromClient)
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
	var encapsulator crypto.Encapsulator
	switch g.kem {
	case kemNone:
		return public, secret, nil
	case kemMLKEM768:
		encapsulator, err = mlkem.NewEncapsulationKey768(encapsulationKey)
	case kemMLKEM1024:
		encapsulator, err = mlkem.NewEncapsulationKey1024(encapsulationKey)
	default:
		return nil, nil, errIllegalParameter
	}
	if err != nil {
		return nil, nil, errIllegalParameter
	}
	defer clear(secret)
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
