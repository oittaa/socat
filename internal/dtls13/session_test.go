package dtls13

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/testcert"
)

type testDatagram struct {
	fromClient bool
	data       []byte
}

func driveSessions(t *testing.T, clientConfig, serverConfig *Config, loss, reorder bool) (*session, *session, *[]testDatagram) {
	t.Helper()
	var packets []testDatagram
	var client, server *session
	droppedClient, droppedServer, droppedFinal := false, false, false
	sender := func(fromClient bool) func([]byte) error {
		return func(data []byte) error {
			if loss {
				if fromClient && !droppedClient {
					droppedClient = true
					return nil
				}
				if !fromClient && !droppedServer {
					droppedServer = true
					return nil
				}
				if !fromClient && server != nil && server.handshake.complete && !droppedFinal {
					droppedFinal = true
					return nil
				}
			}
			packets = append(packets, testDatagram{fromClient, bytes.Clone(data)})
			return nil
		}
	}
	var err error
	now := time.Unix(100, 0)
	server, err = newTestServerSession(serverConfig, sender(false))
	if err != nil {
		t.Fatal(err)
	}
	client, err = newClientSession(clientConfig, sender(true), now)
	if err != nil {
		t.Fatal(err)
	}
	for step := 0; step < 2000; step++ {
		if len(packets) != 0 {
			index := 0
			if reorder {
				index = len(packets) - 1
			}
			packet := packets[index]
			packets = append(packets[:index], packets[index+1:]...)
			destination := client
			if packet.fromClient {
				destination = server
			}
			data, err := destination.receive(packet.data, now)
			if err != nil {
				t.Fatalf("receive (client=%t): %v", destination.handshake.client, err)
			}
			if len(data) != 0 {
				t.Fatal("handshake delivered application data")
			}
			continue
		}
		if client.handshake.complete && server.handshake.complete && client.outbound.complete {
			if loss && (!droppedClient || !droppedServer || !droppedFinal) {
				t.Fatal("fault injection did not exercise all selected losses")
			}
			return client, server, &packets
		}
		next := client.deadline()
		if candidate := server.deadline(); next.IsZero() || !candidate.IsZero() && candidate.Before(next) {
			next = candidate
		}
		if next.IsZero() {
			t.Fatal("handshake stalled without a recovery timer")
		}
		now = next
		if err := client.tick(now); err != nil {
			t.Fatal(err)
		}
		if err := server.tick(now); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("handshake exceeded deterministic event bound")
	return nil, nil, nil
}

func TestSessionLossReorderingAndFinalACK(t *testing.T) {
	for _, loss := range []bool{false, true} {
		for _, reorder := range []bool{false, true} {
			t.Run(fmt.Sprintf("loss=%t/reorder=%t", loss, reorder), func(t *testing.T) {
				clientConfig, serverConfig := handshakeConfigs(t)
				clientConfig.MTU = 256
				serverConfig.MTU = 256
				client, server, packets := driveSessions(t, clientConfig, serverConfig, loss, reorder)
				marker := []byte("authenticated application datagram")
				if err := client.application(marker); err != nil {
					t.Fatal(err)
				}
				if len(*packets) != 1 {
					t.Fatalf("application packet count: %d", len(*packets))
				}
				packet := (*packets)[0].data
				for i := 0; i < 2; i++ {
					got, err := server.receive(packet, time.Unix(1000, 0))
					if err != nil {
						t.Fatal(err)
					}
					if i == 0 && (len(got) != 1 || !bytes.Equal(got[0], marker)) {
						t.Fatal("application datagram changed")
					}
					if i == 1 && len(got) != 0 {
						t.Fatal("duplicate application record delivered")
					}
				}
				if !client.deadline().IsZero() || !server.deadline().IsZero() {
					t.Fatal("completed handshake retained a retransmission timer")
				}
			})
		}
	}
}

func TestSessionLargeCertificateFlight(t *testing.T) {
	ca, err := testcert.NewAuthority("large certificate CA")
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"localhost"}
	for i := range 200 {
		names = append(names, fmt.Sprintf("host%03d.example.test", i))
	}
	leaf, err := ca.Leaf("localhost", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil, names)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	client := &Config{ServerName: "localhost", RootCAs: roots, MTU: 256}
	server := &Config{Certificates: []tls.Certificate{leaf.TLS()}, MTU: 256}
	driveSessions(t, client, server, true, true)
}
