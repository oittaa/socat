package dtls13

import (
	"crypto/tls"
	"crypto/x509"
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
