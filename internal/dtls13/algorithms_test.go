package dtls13

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"
)

func mldsaCertificate(t *testing.T, parameters mldsa.Parameters) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, err := mldsa.GenerateKey(parameters)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ML-DSA CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, template, template, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	key, err := mldsa.GenerateKey(parameters)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: template.NotBefore, NotAfter: template.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}, roots
}

func TestGroupRetryNegotiation(t *testing.T) {
	for _, group := range []tls.CurveID{tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024, tls.CurveP256, tls.CurveP384, tls.CurveP521} {
		t.Run(group.String(), func(t *testing.T) {
			clientConfig, serverConfig := handshakeConfigs(t)
			serverConfig.CurvePreferences = []tls.CurveID{group}
			client, server, err := runHandshake(t, clientConfig, serverConfig)
			if err != nil {
				t.Fatal(err)
			}
			retry, err := parseServerHello(server.retryHello[4:])
			share := wireReader{data: retry.extensions[extKeyShare]}
			requested := share.uint16()
			if err != nil || share.done() != nil || requested != uint16(group) || client.state.CurveID != group || server.state.CurveID != group {
				t.Fatal("HelloRetryRequest did not negotiate the requested group")
			}
		})
	}
}

func TestPostQuantumHandshakeLoss(t *testing.T) {
	for _, parameters := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(parameters.String(), func(t *testing.T) {
			cert, roots := mldsaCertificate(t, parameters)
			client := &Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, ServerName: "localhost", MTU: 256, CipherSuites: []uint16{chaCha20Poly1305}}
			server := &Config{Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MTU: 256, CipherSuites: []uint16{chaCha20Poly1305}}
			a, b, packets := driveSessions(t, client, server, true, true)
			if a.handshake.state.CurveID != tls.X25519MLKEM768 || b.handshake.state.CurveID != tls.X25519MLKEM768 || len(a.handshake.state.VerifiedChains) == 0 || len(b.handshake.state.VerifiedChains) == 0 {
				t.Fatal("post-quantum handshake was not verified")
			}
			if err := a.application([]byte("post-quantum data")); err != nil {
				t.Fatal(err)
			}
			got, err := b.receive((*packets)[0].data, time.Unix(1000, 0))
			if err != nil || len(got) != 1 || string(got[0]) != "post-quantum data" {
				t.Fatalf("application exchange: %q, %v", got, err)
			}
		})
	}
}

type messageOnlySigner struct {
	crypto.Signer
	called bool
}

func (s *messageOnlySigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("Sign must not be used")
}
func (s *messageOnlySigner) SignMessage(r io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.called = true
	return crypto.SignMessage(s.Signer, r, msg, opts)
}

func TestOpaqueMessageSigner(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	signer := &messageOnlySigner{Signer: key}
	transcript := make([]byte, 32)
	wire, err := signCertificateVerify(signer, uint16(tls.PSSWithSHA256), transcript, true)
	if err != nil || !signer.called {
		t.Fatalf("opaque SignMessage was not used: %v", err)
	}
	if err := verifyCertificateVerify(key.Public(), signatureSchemes, wire, transcript, true); err != nil {
		t.Fatal(err)
	}
	if keySupportsSignature(key.Public(), uint16(tls.PSSWithSHA512)) {
		t.Fatal("accepted an RSA key too small to encode this PSS signature")
	}
}
