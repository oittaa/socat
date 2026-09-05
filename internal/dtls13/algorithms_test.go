package dtls13

import (
	"bytes"
	"context"
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
	"net"
	"slices"
	"testing"
	"time"
)

// Probe the public TLS API so a Go upgrade cannot silently leave DTLS behind.
func TestGoTLS13AlgorithmDefaults(t *testing.T) {
	t.Setenv("GODEBUG", "")
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	observed := make(chan *tls.ClientHelloInfo, 1)
	done := make(chan error, 1)
	server := tls.Server(b, &tls.Config{MinVersion: tls.VersionTLS13, GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		observed <- info
		return nil, errors.New("capability probe complete")
	}})
	go func() { done <- server.HandshakeContext(ctx) }()
	client := tls.Client(a, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ServerName: "localhost"})
	_ = client.HandshakeContext(ctx)
	if err := <-done; err == nil {
		t.Fatal("probe unexpectedly completed a handshake")
	}
	var info *tls.ClientHelloInfo
	select {
	case info = <-observed:
	default:
		t.Fatal("Go did not send a ClientHello")
	}
	groups := defaultGroups()
	if !slices.Equal(groups, info.SupportedCurves) {
		t.Fatalf("Go key exchanges changed: DTLS %v; Go %v; integrate or document the difference", groups, info.SupportedCurves)
	}
	var signatures []uint16
	for _, id := range info.SignatureSchemes {
		signatures = append(signatures, uint16(id))
	}
	want := slices.Clone(signatureSchemes)
	if !slices.Equal(signatures, want) {
		t.Fatalf("Go signatures changed: DTLS %x; Go %x", want, signatures)
	}
	suites := defaultCipherSuites()
	slices.Sort(suites)
	slices.Sort(info.CipherSuites)
	if !slices.Equal(suites, info.CipherSuites) {
		t.Fatalf("Go ciphers changed: DTLS %x; Go %x", suites, info.CipherSuites)
	}
}

func TestHybridKeyShares(t *testing.T) {
	for _, tc := range []struct {
		group                              tls.CurveID
		clientSize, serverSize, secretSize int
		kemFirst                           bool
	}{
		{tls.X25519MLKEM768, 1216, 1120, 64, true},
		{tls.SecP256r1MLKEM768, 1249, 1153, 64, false},
		{tls.SecP384r1MLKEM1024, 1665, 1665, 80, false},
	} {
		t.Run(tc.group.String(), func(t *testing.T) {
			client, err := generateShare(uint16(tc.group))
			if err != nil {
				t.Fatal(err)
			}
			server, secret, err := serverShare(uint16(tc.group), client.public)
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.shared(server)
			if err != nil || !bytes.Equal(got, secret) {
				t.Fatalf("hybrid secret disagreement: %v", err)
			}
			if len(client.public) != tc.clientSize || len(server) != tc.serverSize || len(secret) != tc.secretSize {
				t.Fatal("RFC 10024 encoding lengths differ")
			}
			key := client.kem.Encapsulator().Bytes()
			if tc.kemFirst && !bytes.HasPrefix(client.public, key) || !tc.kemFirst && !bytes.HasSuffix(client.public, key) {
				t.Fatal("incorrect component order")
			}
			for _, invalid := range [][]byte{nil, server[:len(server)-1], append(bytes.Clone(server), 0)} {
				if _, err := client.shared(invalid); !errors.Is(err, errIllegalParameter) {
					t.Fatalf("accepted invalid server share: %v", err)
				}
			}
			bad := bytes.Clone(client.public)
			kemOffset := 0
			if !tc.kemFirst {
				kemOffset = len(bad) - len(key)
			}
			copy(bad[kemOffset:], []byte{255, 255, 255})
			if _, _, err := serverShare(uint16(tc.group), bad); !errors.Is(err, errIllegalParameter) {
				t.Fatalf("accepted noncanonical ML-KEM key: %v", err)
			}
			bad = bytes.Clone(server)
			ecOffset, ecSize := 0, len(client.ecdh.PublicKey().Bytes())
			if tc.kemFirst {
				ecOffset = len(bad) - ecSize
			}
			clear(bad[ecOffset : ecOffset+ecSize])
			if _, err := client.shared(bad); !errors.Is(err, errIllegalParameter) {
				t.Fatalf("accepted invalid ECDHE component: %v", err)
			}
			bad = bytes.Clone(server)
			kemOffset = ecSize
			if tc.kemFirst {
				kemOffset = 0
			}
			bad[kemOffset] ^= 1
			other, err := client.shared(bad)
			if err != nil || bytes.Equal(other, secret) {
				t.Fatal("ML-KEM ciphertext alteration did not implicitly reject to a different secret")
			}
		})
	}
}

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
