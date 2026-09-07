package dtls13

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/testcert"
)

type limitedDatagramConn struct {
	net.PacketConn
	limit   int
	maxSent int
}

func (c *limitedDatagramConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.limit > 0 && len(p) > c.limit {
		return 0, &net.OpError{Op: "write", Net: "udp", Err: messageTooLongError()}
	}
	if len(p) > c.maxSent {
		c.maxSent = len(p)
	}
	return c.PacketConn.WriteTo(p, addr)
}

func driveLimitedSessions(t *testing.T, clientConfig, serverConfig *Config, clientLimit, serverLimit int, dropUntil int) (*session, *session, map[string]struct{}) {
	t.Helper()
	var packets []testDatagram
	seen := make(map[string]struct{})
	var client, server *session
	sender := func(fromClient bool, limit int) func([]byte) error {
		return func(data []byte) error {
			if dropUntil > 0 && fromClient && (client == nil || client.mtuReductions < dropUntil) {
				return nil
			}
			if limit > 0 && len(data) > limit {
				return messageTooLongError()
			}
			key := string(data)
			if _, ok := seen[key]; ok {
				t.Fatal("retransmitted an identical datagram")
			}
			seen[key] = struct{}{}
			packets = append(packets, testDatagram{fromClient, bytes.Clone(data)})
			return nil
		}
	}
	now := time.Unix(100, 0)
	var err error
	server, err = newTestServerSession(serverConfig, sender(false, serverLimit))
	if err != nil {
		t.Fatal(err)
	}
	client, err = newClientSession(clientConfig, sender(true, clientLimit), now)
	if err != nil {
		t.Fatal(err)
	}
	for step := 0; step < 4000; step++ {
		if len(packets) != 0 {
			p := packets[0]
			packets = packets[1:]
			destination := client
			if p.fromClient {
				destination = server
			}
			if _, err := destination.receive(p.data, now); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if client.handshake.complete && server.handshake.complete && client.outbound.complete {
			return client, server, seen
		}
		next := client.deadline()
		if candidate := server.deadline(); next.IsZero() || !candidate.IsZero() && candidate.Before(next) {
			next = candidate
		}
		if next.IsZero() {
			t.Fatal("handshake stalled")
		}
		now = next
		if err := client.tick(now); err != nil {
			t.Fatal(err)
		}
		if err := server.tick(now); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("handshake did not finish")
	return nil, nil, nil
}

func TestHandshakeRecoversFromEMSGSIZE(t *testing.T) {
	limitedCfg, peerCfg := handshakeConfigs(t)
	limitedCfg.MTU, peerCfg.MTU = 4000, 4000
	limited, peer, _ := driveLimitedSessions(t, limitedCfg, peerCfg, 600, 0, 0)
	if limited.mtuReductions == 0 || limited.effectiveMTU() >= 4000 || limited.effectiveMTU() < minPathMTU {
		t.Fatalf("limited MTU %d after %d reductions", limited.effectiveMTU(), limited.mtuReductions)
	}
	if peer.mtuReductions != 0 || peer.effectiveMTU() != 4000 {
		t.Fatalf("unlimited peer shrank: mtu=%d reductions=%d", peer.effectiveMTU(), peer.mtuReductions)
	}
	if err := limited.application([]byte("ok")); err != nil {
		t.Fatal(err)
	}
}

func TestHandshakeEMSGSIZEIsolatedFromSecondAssociation(t *testing.T) {
	aClient, aServer := handshakeConfigs(t)
	bClient, bServer := handshakeConfigs(t)
	aClient.MTU, aServer.MTU, bClient.MTU, bServer.MTU = 4000, 4000, 4000, 4000
	limited, _, _ := driveLimitedSessions(t, aClient, aServer, 600, 0, 0)
	plain, _, _ := driveLimitedSessions(t, bClient, bServer, 0, 0, 0)
	if limited.mtuReductions == 0 {
		t.Fatal("injected EMSGSIZE did not shrink")
	}
	if plain.mtuReductions != 0 || plain.effectiveMTU() != 4000 {
		t.Fatalf("second association shrank: mtu=%d reductions=%d", plain.effectiveMTU(), plain.mtuReductions)
	}
}

func TestHandshakeShrinksOnUnansweredFlight(t *testing.T) {
	clientCfg, serverCfg := handshakeConfigs(t)
	clientCfg.MTU, serverCfg.MTU = 2000, 2000
	client, server, _ := driveLimitedSessions(t, clientCfg, serverCfg, 0, 0, 2)
	if client.mtuReductions < 2 || client.mtuReductions > maxMTUReductions {
		t.Fatalf("unanswered reductions = %d", client.mtuReductions)
	}
	if client.effectiveMTU() >= 2000 || client.effectiveMTU() < minPathMTU {
		t.Fatalf("unanswered MTU %d", client.effectiveMTU())
	}
	if server.effectiveMTU() != 2000 {
		t.Fatalf("server shrank without sending: %d", server.effectiveMTU())
	}
}

func TestOrdinaryHandshakeLossDoesNotShrinkEndlessly(t *testing.T) {
	ca, err := testcert.NewAuthority("pmtu ordinary-loss CA")
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
	clientCfg := &Config{ServerName: "localhost", RootCAs: roots, MTU: 2000}
	serverCfg := &Config{Certificates: []tls.Certificate{leaf.TLS()}, MTU: 2000}
	var packets []testDatagram
	var client, server *session
	var serverRecords int
	dropped := false
	sender := func(fromClient bool) func([]byte) error {
		return func(data []byte) error {
			if !fromClient {
				serverRecords++
				if !dropped && serverRecords == 3 {
					dropped = true
					return nil
				}
			}
			packets = append(packets, testDatagram{fromClient, bytes.Clone(data)})
			return nil
		}
	}
	now := time.Unix(100, 0)
	server, err = newTestServerSession(serverCfg, sender(false))
	if err != nil {
		t.Fatal(err)
	}
	client, err = newClientSession(clientCfg, sender(true), now)
	if err != nil {
		t.Fatal(err)
	}
	for step := 0; step < 4000; step++ {
		if len(packets) != 0 {
			p := packets[0]
			packets = packets[1:]
			destination := client
			if p.fromClient {
				destination = server
			}
			if _, err := destination.receive(p.data, now); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if client.handshake.complete && server.handshake.complete && client.outbound.complete {
			if !dropped || serverRecords < 4 {
				t.Fatalf("loss did not land in a multi-record server flight: dropped=%t records=%d", dropped, serverRecords)
			}
			if client.mtuReductions != 0 || server.mtuReductions != 0 {
				t.Fatalf("ACK progress shrank MTU: client=%d server=%d", client.mtuReductions, server.mtuReductions)
			}
			if client.effectiveMTU() != 2000 || server.effectiveMTU() != 2000 {
				t.Fatalf("ACK progress changed MTU: client=%d server=%d", client.effectiveMTU(), server.effectiveMTU())
			}
			return
		}
		next := client.deadline()
		if candidate := server.deadline(); next.IsZero() || !candidate.IsZero() && candidate.Before(next) {
			next = candidate
		}
		if next.IsZero() {
			t.Fatal("handshake stalled")
		}
		now = next
		if err := client.tick(now); err != nil {
			t.Fatal(err)
		}
		if err := server.tick(now); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("handshake did not finish")
}

func TestApplicationWriteDoesNotRecoverEMSGSIZE(t *testing.T) {
	clientCfg, serverCfg := handshakeConfigs(t)
	client, _, packets := driveSessions(t, clientCfg, serverCfg, false, false)
	before := client.effectiveMTU()
	reductions := client.mtuReductions
	client.send = func([]byte) error { return messageTooLongError() }
	if err := client.application([]byte("app")); !isMessageTooLong(err) {
		t.Fatalf("application EMSGSIZE: %v", err)
	}
	if client.effectiveMTU() != before || client.mtuReductions != reductions {
		t.Fatal("application write recovered through handshake MTU path")
	}
	if err := client.application([]byte("still")); !isMessageTooLong(err) {
		t.Fatalf("second application write: %v", err)
	}
	if len(*packets) != 0 {
		t.Fatal("application datagram was recovered")
	}
}

func TestConnHandshakeRecoversFromWriteToEMSGSIZE(t *testing.T) {
	a, b := handshakeConfigs(t)
	a.MTU, b.MTU = 4000, 4000
	a.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	b.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	listener, err := Listen(testUDP(t), b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	transport := &limitedDatagramConn{PacketConn: testUDP(t), limit: 600}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := Client(ctx, transport, listener.Addr(), a)
	if err != nil {
		if errors.Is(err, errRecordOverflow) {
			t.Fatal("EMSGSIZE was routed through record_overflow")
		}
		t.Fatalf("handshake: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	peer, err := listener.AcceptContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	server := peer.(*Conn)
	t.Cleanup(func() { _ = server.Close() })
	if client.MaxDatagramSize() >= 4000-22 {
		t.Fatalf("MaxDatagramSize %d was not reduced", client.MaxDatagramSize())
	}
	if transport.maxSent > 600 {
		t.Fatalf("path still accepted oversized datagram %d", transport.maxSent)
	}
	for _, c := range []*Conn{client, server} {
		if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	marker := []byte("pmtu-echo")
	if _, err := client.Write(marker); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, err := server.Read(buffer)
	if err != nil || !bytes.Equal(buffer[:n], marker) {
		t.Fatalf("echo: %q, %v", buffer[:n], err)
	}
}
