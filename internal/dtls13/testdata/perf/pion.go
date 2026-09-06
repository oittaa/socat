package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
)

const library = "pion"

func pair(cert tls.Certificate, roots *x509.CertPool) (net.Conn, net.Conn, func()) {
	// A successful handshake has only one permitted version, cipher, and group.
	listener, err := dtls.ListenAddr("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		dtls.WithCertificates(cert), dtls.WithMinVersion(protocol.Version1_3), dtls.WithMaxVersion(protocol.Version1_3),
		dtls.WithCipherSuites(ciphersuite.TLS_AES_128_GCM_SHA256), dtls.WithEllipticCurves(elliptic.X25519), dtls.WithMTU(1200))
	must(err)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	accepted := make(chan net.Conn, 1)
	go func() {
		server, e := listener.Accept()
		must(e)
		must(server.(*dtls.Conn).HandshakeContext(ctx))
		accepted <- server
	}()
	client, err := dtls.Client(socket(), listener.Addr(), dtls.WithRootCAs(roots), dtls.WithServerName("localhost"),
		dtls.WithMinVersion(protocol.Version1_3), dtls.WithMaxVersion(protocol.Version1_3),
		dtls.WithCipherSuites(ciphersuite.TLS_AES_128_GCM_SHA256), dtls.WithEllipticCurves(elliptic.X25519), dtls.WithMTU(1200))
	must(err)
	must(client.HandshakeContext(ctx))
	state, ok := client.ConnectionState()
	if !ok || state.CipherSuiteID != ciphersuite.TLS_AES_128_GCM_SHA256 {
		panic("unexpected negotiation")
	}
	server := <-accepted
	return client, server, func() { client.Close(); server.Close(); listener.Close() }
}
