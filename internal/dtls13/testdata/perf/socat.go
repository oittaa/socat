package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	"github.com/oittaa/socat/internal/dtls13"
)

const library = "socat"

func pair(cert tls.Certificate, roots *x509.CertPool) (net.Conn, net.Conn, func()) {
	config := &dtls13.Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, ServerName: "localhost", MTU: 1200, DisableMigration: true, CurvePreferences: []tls.CurveID{tls.X25519}, CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256}}
	listener, err := dtls13.Listen(socket(), config)
	must(err)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := dtls13.Client(ctx, socket(), listener.Addr(), config)
	must(err)
	server, err := listener.AcceptContext(ctx)
	must(err)
	state := client.ConnectionState()
	if state.Version != 0xfefc || state.CipherSuite != tls.TLS_AES_128_GCM_SHA256 || state.CurveID != tls.X25519 {
		panic("unexpected negotiation")
	}
	return client, server, func() { client.Close(); server.Close(); listener.Close() }
}
