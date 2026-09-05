package dtls13

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

func verifyPeer(config *Config, raw [][]byte, client bool) ([]*x509.Certificate, [][]*x509.Certificate, error) {
	certificates, err := parseCertificateChain(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", errBadCertificate, err)
	}
	if len(certificates) == 0 && (client || config.ClientAuth == tls.RequireAnyClientCert || config.ClientAuth == tls.RequireAndVerifyClientCert) {
		return nil, nil, errCertificateRequired
	}
	for _, cert := range certificates {
		if key, ok := cert.PublicKey.(*rsa.PublicKey); ok && (key.N.BitLen() < 2048 || key.N.BitLen() > 8192) {
			return nil, nil, fmt.Errorf("%w: RSA key size outside 2048–8192 bits", errBadCertificate)
		}
	}
	if len(certificates) != 0 && certificates[0].KeyUsage != 0 && certificates[0].KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, nil, fmt.Errorf("%w: certificate does not permit digital signatures", errBadCertificate)
	}
	var chains [][]*x509.Certificate
	verify := client && !config.InsecureSkipVerify || !client && config.ClientAuth >= tls.VerifyClientCertIfGiven
	if verify && len(certificates) != 0 {
		opts := x509.VerifyOptions{Roots: config.RootCAs, Intermediates: x509.NewCertPool(), CurrentTime: config.now(), DNSName: config.ServerName}
		if !client {
			opts.Roots = config.ClientCAs
			opts.DNSName = ""
			opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		for _, cert := range certificates[1:] {
			opts.Intermediates.AddCert(cert)
		}
		chains, err = certificates[0].Verify(opts)
		if err != nil {
			alert := errBadCertificate
			var unknown x509.UnknownAuthorityError
			var invalid x509.CertificateInvalidError
			if errors.As(err, &unknown) {
				alert = errUnknownCA
			}
			if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
				alert = errCertificateExpired
			}
			return nil, nil, fmt.Errorf("%w: %v", alert, err)
		}
	}
	if config.VerifyPeerCertificate != nil {
		if err := config.VerifyPeerCertificate(raw, chains); err != nil {
			return nil, nil, fmt.Errorf("%w: %v", errBadCertificate, err)
		}
	}
	return certificates, chains, nil
}
