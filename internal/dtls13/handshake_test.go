package dtls13

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
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

func TestCertificateHandshakeMatrix(t *testing.T) {
	clientConfig, serverConfig := handshakeConfigs(t)
	for _, suite := range defaultCipherSuites() {
		for _, group := range defaultGroups() {
			for _, mutual := range []bool{false, true} {
				t.Run(fmt.Sprintf("%x/%d/mutual=%t", suite, group, mutual), func(t *testing.T) {
					clientCopy, serverCopy := *clientConfig, *serverConfig
					clientCopy.CipherSuites = []uint16{suite}
					serverCopy.CipherSuites = []uint16{suite}
					clientCopy.CurvePreferences = []tls.CurveID{group}
					serverCopy.CurvePreferences = []tls.CurveID{group}
					clientCopy.NextProtos = []string{"second", "first"}
					serverCopy.NextProtos = []string{"first", "second"}
					if !mutual {
						serverCopy.ClientAuth = tls.NoClientCert
						clientCopy.Certificates = nil
					}
					client, server, err := runHandshake(t, &clientCopy, &serverCopy)
					if err != nil {
						t.Fatal(err)
					}
					if !client.retried || !client.rrc || !server.rrc || !client.cidNegotiated || !server.cidNegotiated {
						t.Fatal("cookie/CID/RRC negotiation missing")
					}
					if !bytes.Equal(client.peerCID, server.localCID) || !bytes.Equal(server.peerCID, client.localCID) {
						t.Fatal("connection IDs disagree")
					}
					if client.state.NegotiatedProtocol != "first" || server.state.NegotiatedProtocol != "first" {
						t.Fatal("server ALPN preference was not selected")
					}
					if !bytes.Equal(client.clientApplication, server.clientApplication) || !bytes.Equal(client.serverApplication, server.serverApplication) {
						t.Fatal("application secrets disagree")
					}
					if client.state.CurveID != group || server.state.CurveID != group || client.state.CipherSuite != suite || server.state.CipherSuite != suite {
						t.Fatal("negotiated algorithms differ from the forced algorithms")
					}
					if len(client.state.VerifiedChains) == 0 || mutual && len(server.state.VerifiedChains) == 0 {
						t.Fatal("certificate chains were not verified")
					}
				})
			}
		}
	}
}

func TestHandshakeAuthenticationFailures(t *testing.T) {
	for _, kind := range []string{"hostname", "authority", "expired", "missing client certificate", "application protocol", "callback"} {
		t.Run(kind, func(t *testing.T) {
			client, server := handshakeConfigs(t)
			want := errBadCertificate
			switch kind {
			case "hostname":
				client.ServerName = "elsewhere.test"
			case "authority":
				client.RootCAs = x509.NewCertPool()
				want = errUnknownCA
			case "expired":
				client.Time = func() time.Time { return time.Now().Add(48 * time.Hour) }
				want = errCertificateExpired
			case "missing client certificate":
				client.Certificates = nil
				want = errCertificateRequired
			case "application protocol":
				client.NextProtos = []string{"a"}
				server.NextProtos = []string{"b"}
				want = errNoApplicationProtocol
			case "callback":
				client.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return fmt.Errorf("rejected by callback") }
			}
			_, _, err := runHandshake(t, client, server)
			if !errors.Is(err, want) {
				t.Fatalf("got %v; want %v", err, want)
			}
		})
	}
}

func TestHandshakeFixedPeerAndOptionalClientCertificate(t *testing.T) {
	client, server := handshakeConfigs(t)
	client.DisableMigration = true
	server.DisableMigration = true
	server.ClientAuth = tls.RequestClientCert
	client.Certificates = nil
	clientCalls, serverCalls := 0, 0
	client.VerifyConnection = func(state tls.ConnectionState) error {
		if !state.HandshakeComplete || state.Version != version13 || len(state.PeerCertificates) == 0 {
			return fmt.Errorf("incomplete client authentication state")
		}
		clientCalls++
		return nil
	}
	server.VerifyConnection = func(state tls.ConnectionState) error {
		if !state.HandshakeComplete || len(state.PeerCertificates) != 0 {
			return fmt.Errorf("incorrect optional client authentication state")
		}
		serverCalls++
		return nil
	}
	a, b, err := runHandshake(t, client, server)
	if err != nil {
		t.Fatal(err)
	}
	if a.cidNegotiated || b.cidNegotiated || a.rrc || b.rrc || clientCalls != 1 || serverCalls != 1 {
		t.Fatal("fixed-peer mode or verification callback contract failed")
	}
}
