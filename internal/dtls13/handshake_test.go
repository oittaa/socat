package dtls13

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/testcert"
)

func handshakeConfigs(t testing.TB) (*Config, *Config) {
	t.Helper()
	ca, err := testcert.NewAuthority("DTLS test CA")
	if err != nil {
		t.Fatal(err)
	}
	server, err := ca.Leaf("localhost", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil, []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	client, err := ca.Leaf("client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	return &Config{ServerName: "localhost", RootCAs: roots, Certificates: []tls.Certificate{client.TLS()}},
		&Config{Certificates: []tls.Certificate{server.TLS()}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}
}

func runHandshake(t *testing.T, clientConfig, serverConfig *Config) (*clientHandshake, *serverHandshake, error) {
	t.Helper()
	client, messages, err := newClientHandshake(clientConfig)
	if err != nil {
		return nil, nil, err
	}
	server, err := newTestServerHandshake(serverConfig)
	if err != nil {
		return nil, nil, err
	}
	peer := netip.MustParseAddrPort("127.0.0.1:10001")
	now := time.Unix(100, 0)
	toServer := true
	for i := 0; i < 8 && len(messages) != 0; i++ {
		var next []handshakeMessage
		for _, m := range messages {
			var reply []handshakeMessage
			if toServer {
				reply, err = server.receive(m, peer, now)
			} else {
				reply, err = client.handle(m)
			}
			if err != nil {
				return client, server.server, err
			}
			next = append(next, reply...)
		}
		messages = next
		toServer = !toServer
	}
	if !client.complete || !server.complete {
		return client, server.server, fmt.Errorf("handshake did not complete")
	}
	return client, server.server, nil
}

func TestInitialClientHelloOneDatagram(t *testing.T) {
	clientConfig, _ := handshakeConfigs(t)
	clientConfig.MTU = 1512
	clientConfig.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	clientConfig.NextProtos = []string{strings.Repeat("a", 130)}
	h, _, err := newClientHandshake(clientConfig)
	n := 0
	_, sendErr := newClientSession(clientConfig, func([]byte) error { n++; return nil }, time.Unix(100, 0))
	if err != nil || sendErr != nil || n != 1 || len(h.shares) != 0 {
		t.Fatalf("initial datagrams = %d, shares = %d, %v, %v", n, len(h.shares), err, sendErr)
	}
}

func TestEmptyClientHelloOverflowHandshake(t *testing.T) {
	clientConfig, serverConfig := handshakeConfigs(t)
	clientConfig.MTU = 256
	clientConfig.NextProtos = []string{strings.Repeat("a", 200)}
	if _, _, err := runHandshake(t, clientConfig, serverConfig); err != nil {
		t.Fatal(err)
	}
}
