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

func TestInitialClientHelloKeyShare(t *testing.T) {
	clientConfig, serverConfig := handshakeConfigs(t)
	_, messages, err := newClientHandshake(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := parseClientOfferFrom(messages[0].body)
	if err != nil || len(offer.shares) != 0 || offer.groups[0] != uint16(tls.X25519MLKEM768) || !clientHelloFitsDatagram(messages[0].body, 1200) {
		t.Fatal("default ClientHello should omit oversized initial key shares")
	}
	client, server, err := runHandshake(t, clientConfig, serverConfig)
	if err != nil || !client.retried || client.state.CurveID != tls.X25519MLKEM768 || server.state.CurveID != tls.X25519MLKEM768 {
		t.Fatal("empty key_share HelloRetryRequest did not negotiate X25519MLKEM768")
	}

	clientConfig, _ = handshakeConfigs(t)
	clientConfig.CurvePreferences = []tls.CurveID{tls.X25519}
	_, messages, err = newClientHandshake(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	offer, err = parseClientOfferFrom(messages[0].body)
	if err != nil || offer.shares[uint16(tls.X25519)] == nil {
		t.Fatal("small ClientHello dropped the X25519 share")
	}

	clientConfig, serverConfig = handshakeConfigs(t)
	clientConfig.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	serverConfig.CurvePreferences = []tls.CurveID{tls.X25519, tls.X25519MLKEM768}
	_, messages, err = newClientHandshake(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	offer, err = parseClientOfferFrom(messages[0].body)
	if err != nil || len(offer.groups) != 1 || offer.groups[0] != uint16(tls.X25519MLKEM768) || len(offer.shares) != 0 {
		t.Fatal("hybrid-only ClientHello advertised a classical group")
	}
	client, server, err = runHandshake(t, clientConfig, serverConfig)
	if err != nil || client.state.CurveID != tls.X25519MLKEM768 || server.state.CurveID != tls.X25519MLKEM768 {
		t.Fatal("hybrid-only configuration negotiated a classical group")
	}

	clientConfig, _ = handshakeConfigs(t)
	clientConfig.MTU = 256
	clientConfig.NextProtos = []string{strings.Repeat("a", 200)}
	_, messages, err = newClientHandshake(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	offer, err = parseClientOfferFrom(messages[0].body)
	if err != nil || len(offer.shares) == 0 {
		t.Fatal("ClientHello that cannot fit even empty shares should fragment with shares")
	}
}

func parseClientOfferFrom(body []byte) (clientOffer, error) {
	hello, err := parseClientHello(body)
	if err != nil {
		return clientOffer{}, err
	}
	return parseClientOffer(hello)
}
