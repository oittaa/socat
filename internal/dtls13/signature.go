package dtls13

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"slices"
)

var errSignature = errors.New("dtls: invalid CertificateVerify signature")

var signatureSchemes = []uint16{
	uint16(tls.ECDSAWithP256AndSHA256), uint16(tls.Ed25519),
	uint16(tls.PSSWithSHA256), uint16(tls.ECDSAWithP384AndSHA384),
	uint16(tls.PSSWithSHA384), uint16(tls.PSSWithSHA512),
	uint16(tls.ECDSAWithP521AndSHA512),
}

func signatureHash(scheme uint16) (crypto.Hash, error) {
	switch tls.SignatureScheme(scheme) {
	case tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256:
		return crypto.SHA256, nil
	case tls.ECDSAWithP384AndSHA384, tls.PSSWithSHA384:
		return crypto.SHA384, nil
	case tls.ECDSAWithP521AndSHA512, tls.PSSWithSHA512:
		return crypto.SHA512, nil
	case tls.Ed25519:
		return crypto.Hash(0), nil
	default:
		return 0, errSignature
	}
}

func keySupportsSignature(public crypto.PublicKey, scheme uint16) bool {
	sig := tls.SignatureScheme(scheme)
	switch key := public.(type) {
	case *rsa.PublicKey:
		return key != nil && key.N != nil && key.N.BitLen() >= 2048 && key.N.BitLen() <= 8192 &&
			(sig == tls.PSSWithSHA256 || sig == tls.PSSWithSHA384 || sig == tls.PSSWithSHA512)
	case *ecdsa.PublicKey:
		if key == nil || key.Curve == nil {
			return false
		}
		bits := key.Curve.Params().BitSize
		return sig == tls.ECDSAWithP256AndSHA256 && bits == 256 || sig == tls.ECDSAWithP384AndSHA384 && bits == 384 || sig == tls.ECDSAWithP521AndSHA512 && bits == 521
	case ed25519.PublicKey:
		return len(key) == ed25519.PublicKeySize && sig == tls.Ed25519
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

func signatureDigest(scheme uint16, transcript []byte, server bool) ([]byte, crypto.SignerOpts, error) {
	if len(transcript) != 32 && len(transcript) != 48 {
		return nil, nil, errSignature
	}
	hash, err := signatureHash(scheme)
	if err != nil {
		return nil, nil, err
	}
	input := certificateVerifyInput(transcript, server)
	var opts crypto.SignerOpts = hash
	if hash != 0 {
		h := hash.New()
		_, _ = h.Write(input)
		input = h.Sum(nil)
	}
	switch tls.SignatureScheme(scheme) {
	case tls.PSSWithSHA256, tls.PSSWithSHA384, tls.PSSWithSHA512:
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash}
	}
	return input, opts, nil
}

func signCertificateVerify(signer crypto.Signer, scheme uint16, transcript []byte, server bool) ([]byte, error) {
	if signer == nil || !keySupportsSignature(signer.Public(), scheme) {
		return nil, errSignature
	}
	digest, opts, err := signatureDigest(scheme, transcript, server)
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(rand.Reader, digest, opts)
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
	scheme := r.uint16()
	sig := r.vector16()
	if r.done() != nil || len(sig) == 0 {
		return errDecode
	}
	if !slices.Contains(offered, scheme) || !keySupportsSignature(public, scheme) {
		return errIllegalParameter
	}
	digest, opts, err := signatureDigest(scheme, transcript, server)
	if err != nil {
		return err
	}
	switch key := public.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPSS(key, opts.HashFunc(), digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: opts.HashFunc()}); err == nil {
			return nil
		}
	case *ecdsa.PublicKey:
		if ecdsa.VerifyASN1(key, digest, sig) {
			return nil
		}
	case ed25519.PublicKey:
		if ed25519.Verify(key, digest, sig) {
			return nil
		}
	}
	return errSignature
}
