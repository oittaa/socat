package dtls13

import (
	"bytes"
	"crypto/x509"
	"errors"
)

const maxCertificates = 64

var errCertificate = errors.New("dtls: invalid certificate message")

func encodeCertificate(chain [][]byte, context []byte) ([]byte, error) {
	if len(chain) > maxCertificates {
		return nil, errHandshakeLimit
	}
	list := wireWriter{}
	for _, der := range chain {
		if len(der) == 0 {
			return nil, errCertificate
		}
		if len(der) > maxHandshakeBody-len(list.data)-5 {
			return nil, errHandshakeLimit
		}
		list.vector24(der)
		list.vector16(nil)
	}
	w := wireWriter{}
	w.vector8(context)
	w.vector24(list.data)
	if len(w.data) > maxHandshakeBody {
		return nil, errHandshakeLimit
	}
	return w.result()
}

func parseCertificate(data, expectedContext []byte) ([][]byte, error) {
	if len(data) > maxHandshakeBody {
		return nil, errHandshakeLimit
	}
	r := wireReader{data: data}
	context := r.vector8()
	list := wireReader{data: r.vector24()}
	if r.done() != nil {
		return nil, errDecode
	}
	if !bytes.Equal(context, expectedContext) {
		return nil, errIllegalParameter
	}
	var chain [][]byte
	for len(list.data) != 0 && list.err == nil {
		if len(chain) == maxCertificates {
			return nil, errHandshakeLimit
		}
		der := list.vector24()
		ext := list.vector16()
		if list.err != nil || len(der) == 0 {
			return nil, errDecode
		}
		// This profile does not request any CertificateEntry extensions.
		if len(ext) != 0 {
			return nil, errUnsupportedExtension
		}
		chain = append(chain, der)
	}
	return chain, list.done()
}

func parseCertificateChain(raw [][]byte) ([]*x509.Certificate, error) {
	if len(raw) > maxCertificates {
		return nil, errHandshakeLimit
	}
	certificates := make([]*x509.Certificate, 0, len(raw))
	for _, der := range raw {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		if cert.Version != 3 {
			return nil, errCertificate
		}
		certificates = append(certificates, cert)
	}
	return certificates, nil
}
