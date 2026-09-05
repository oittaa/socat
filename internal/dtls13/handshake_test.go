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

func handshakeConfigs(t *testing.T) (*Config, *Config) {
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

type handshakeEndpoint struct {
	state      *handshakeState
	handle     func(handshakeMessage) ([]handshakeMessage, error)
	reassembly reassembler
	windows    map[uint64]*replayWindow
	sequence   map[uint64]uint64
}

func transferHandshake(t *testing.T, sender, receiver *handshakeEndpoint, messages []handshakeMessage) ([]handshakeMessage, error) {
	t.Helper()
	var response []handshakeMessage
	for _, message := range messages {
		var records [][]byte
		for offset := 0; offset < len(message.body) || len(message.body) == 0; {
			length := min(max(83, (len(message.body)+63)/64), len(message.body)-offset)
			fragment := fragmentFor(t, message, offset, length)
			number := recordNumber{message.epoch, sender.sequence[message.epoch]}
			sender.sequence[message.epoch]++
			var packet []byte
			var err error
			if message.epoch == 0 {
				packet, err = encodePlainRecord(contentHandshake, number.sequence, fragment)
			} else {
				secret := sender.state.schedule.serverHandshake
				if sender.state.client {
					secret = sender.state.schedule.clientHandshake
				}
				keys, e := newTrafficKeys(sender.state.state.CipherSuite, secret)
				if e != nil {
					t.Fatal(e)
				}
				packet, err = keys.encodeRecord(number, sender.state.peerCID, contentHandshake, fragment, 0)
			}
			if err != nil {
				t.Fatal(err)
			}
			records = append(records, packet)
			offset += length
			if len(message.body) == 0 {
				break
			}
		}
		// Reverse fragment delivery to exercise out-of-order decryption and reassembly.
		for i := len(records) - 1; i >= 0; i-- {
			r, rest, err := parseRecord(records[i], len(receiver.state.localCID))
			if err != nil || len(rest) != 0 {
				t.Fatalf("record parse: %v", err)
			}
			body := r.body
			if r.encrypted {
				secret := receiver.state.schedule.clientHandshake
				if receiver.state.client {
					secret = receiver.state.schedule.serverHandshake
				}
				keys, e := newTrafficKeys(receiver.state.state.CipherSuite, secret)
				if e != nil {
					t.Fatal(e)
				}
				window := receiver.windows[message.epoch]
				if window == nil {
					window = &replayWindow{}
					receiver.windows[message.epoch] = window
				}
				_, typ, plain, err := keys.decodeRecord(r, message.epoch, receiver.state.localCID, window)
				if err != nil || typ != contentHandshake {
					t.Fatalf("handshake decryption: %v", err)
				}
				body = plain
			}
			if accepted, err := receiver.reassembly.add(body, message.epoch); !accepted || err != nil {
				t.Fatalf("reassembly: %t, %v", accepted, err)
			}
			for {
				complete, ok := receiver.reassembly.pop()
				if !ok {
					break
				}
				reply, err := receiver.handle(complete)
				if err != nil {
					return nil, err
				}
				response = append(response, reply...)
			}
		}
	}
	return response, nil
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
	a := &handshakeEndpoint{state: client.handshakeState, handle: client.handle, windows: make(map[uint64]*replayWindow), sequence: make(map[uint64]uint64)}
	b := &handshakeEndpoint{state: server.handshakeState, handle: func(m handshakeMessage) ([]handshakeMessage, error) {
		return server.receive(m, netip.MustParseAddrPort("127.0.0.1:10001"), time.Unix(100, 0))
	}, windows: make(map[uint64]*replayWindow), sequence: make(map[uint64]uint64)}
	for i := 0; i < 8 && len(messages) != 0; i++ {
		messages, err = transferHandshake(t, a, b, messages)
		if err != nil {
			return client, server.server, err
		}
		a, b = b, a
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
