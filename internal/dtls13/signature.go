package dtls13

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"slices"
)

var errSignature = errors.New("dtls: invalid CertificateVerify signature")

const maxRSAKeyBits = 8192

type signatureAlgorithm struct {
	id    tls.SignatureScheme
	x509  x509.SignatureAlgorithm
	opts  crypto.SignerOpts
	curve elliptic.Curve
	mldsa mldsa.Parameters
}

var signatureAlgorithms = []signatureAlgorithm{
	{id: tls.MLDSA44, x509: x509.MLDSA44, opts: crypto.Hash(0), mldsa: mldsa.MLDSA44()},
	{id: tls.MLDSA65, x509: x509.MLDSA65, opts: crypto.Hash(0), mldsa: mldsa.MLDSA65()},
	{id: tls.MLDSA87, x509: x509.MLDSA87, opts: crypto.Hash(0), mldsa: mldsa.MLDSA87()},
	{id: tls.PSSWithSHA256, x509: x509.SHA256WithRSAPSS, opts: &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash}},
	{id: tls.ECDSAWithP256AndSHA256, x509: x509.ECDSAWithSHA256, opts: crypto.SHA256, curve: elliptic.P256()},
	{id: tls.Ed25519, x509: x509.PureEd25519, opts: crypto.Hash(0)},
	{id: tls.PSSWithSHA384, x509: x509.SHA384WithRSAPSS, opts: &rsa.PSSOptions{Hash: crypto.SHA384, SaltLength: rsa.PSSSaltLengthEqualsHash}},
	{id: tls.PSSWithSHA512, x509: x509.SHA512WithRSAPSS, opts: &rsa.PSSOptions{Hash: crypto.SHA512, SaltLength: rsa.PSSSaltLengthEqualsHash}},
	{id: tls.ECDSAWithP384AndSHA384, x509: x509.ECDSAWithSHA384, opts: crypto.SHA384, curve: elliptic.P384()},
	{id: tls.ECDSAWithP521AndSHA512, x509: x509.ECDSAWithSHA512, opts: crypto.SHA512, curve: elliptic.P521()},
}

var signatureSchemes = func() []uint16 {
	ids := make([]uint16, 0, len(signatureAlgorithms))
	for _, algorithm := range signatureAlgorithms {
		ids = append(ids, uint16(algorithm.id))
	}
	return ids
}()

func signatureFor(id uint16) (signatureAlgorithm, error) {
	for _, algorithm := range signatureAlgorithms {
		if uint16(algorithm.id) == id {
			return algorithm, nil
		}
	}
	return signatureAlgorithm{}, errSignature
}

func keySupportsSignature(public crypto.PublicKey, scheme uint16) bool {
	a, err := signatureFor(scheme)
	if err != nil {
		return false
	}
	switch key := public.(type) {
	case *rsa.PublicKey:
		_, pss := a.opts.(*rsa.PSSOptions)
		// Match Go's RSA verification work limit and the PSS encoding minimum.
		return pss && key != nil && key.N != nil && key.N.BitLen() <= maxRSAKeyBits && (key.N.BitLen()-1+7)/8 >= 2*a.opts.HashFunc().Size()+2
	case *ecdsa.PublicKey:
		return key != nil && a.curve != nil && key.Curve == a.curve
	case ed25519.PublicKey:
		return len(key) == ed25519.PublicKeySize && a.id == tls.Ed25519
	case *mldsa.PublicKey:
		return key != nil && key.Parameters() == a.mldsa
	default:
		return false
	}
}

func selectSignature(public crypto.PublicKey, offered []uint16) (uint16, error) {
	for _, scheme := range signatureSchemes {
		if slices.Contains(offered, scheme) && keySupportsSignature(public, scheme) {
			return scheme, nil
		}
	}
	return 0, errSignature
}

func certificateVerifyInput(transcript []byte, server bool) []byte {
	context := "TLS 1.3, client CertificateVerify"
	if server {
		context = "TLS 1.3, server CertificateVerify"
	}
	b := bytes.Repeat([]byte{0x20}, 64)
	b = append(b, context...)
	b = append(b, 0)
	return append(b, transcript...)
}

func signatureInput(scheme uint16, transcript []byte, server bool) ([]byte, signatureAlgorithm, error) {
	if len(transcript) != 32 && len(transcript) != 48 {
		return nil, signatureAlgorithm{}, errSignature
	}
	algorithm, err := signatureFor(scheme)
	if err != nil {
		return nil, algorithm, err
	}
	return certificateVerifyInput(transcript, server), algorithm, nil
}

func signCertificateVerify(signer crypto.Signer, scheme uint16, transcript []byte, server bool) ([]byte, error) {
	if signer == nil || !keySupportsSignature(signer.Public(), scheme) {
		return nil, errSignature
	}
	input, algorithm, err := signatureInput(scheme, transcript, server)
	if err != nil {
		return nil, err
	}
	sig, err := crypto.SignMessage(signer, rand.Reader, input, algorithm.opts)
	if err != nil {
		return nil, err
	}
	w := wireWriter{}
	w.uint16(scheme)
	w.vector16(sig)
	return w.result()
}

func verifyCertificateVerify(public crypto.PublicKey, offered []uint16, data, transcript []byte, server bool) error {
	r := wireReader{data: data}
	scheme, sig := r.uint16(), r.vector16()
	if r.done() != nil || len(sig) == 0 {
		return errDecode
	}
	if !slices.Contains(offered, scheme) || !keySupportsSignature(public, scheme) {
		return errIllegalParameter
	}
	input, algorithm, err := signatureInput(scheme, transcript, server)
	if err != nil {
		return err
	}
	certificate := &x509.Certificate{PublicKey: public}
	if certificate.CheckSignature(algorithm.x509, input, sig) != nil {
		return errSignature
	}
	return nil
}
